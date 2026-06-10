#include <dcsystem/system.hpp>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <deepseek/deepseek.hpp>
#include <fstream>
#include <sql.h>
#include <sqlext.h>
#include <cstring>

#include "rapidjson/prettywriter.h"

#define __SERVER_DEBUG__

#ifdef __SERVER_DEBUG__
#include <dpfsdebug.hpp>
#endif

enum class jsonFieldType : uint8_t {
    IsString = 0,
    IsInt64,
    IsInt,
    IsArray,
    IsObject,
};

std::string g_connStr = "127.0.0.1:20500";
std::string g_apiKey = "";

// MySQL RBAC 配置
std::string g_mysqlHost     = "127.0.0.1";
int         g_mysqlPort     = 3306;
std::string g_mysqlUser     = "root";
std::string g_mysqlPasswd   = "";
std::string g_mysqlDatabase = "dpfs";

std::string g_aiPromptTemplate = "";
std::string g_aiPromptTemplate4trace = "";

CSystem::CSystem() {

}

CSystem::~CSystem() {

}

int CSystem::init(const initSystemInfo& initInfo) {
    // std::string g_connStr = ip + ":" + port;
    // cout << "connecting to " << g_connStr << endl;

    g_connStr = initInfo.connStr;
    g_apiKey = initInfo.apiKey;
    g_mysqlHost     = initInfo.mysqlHost;
    g_mysqlPort     = initInfo.mysqlPort;
    g_mysqlUser     = initInfo.mysqlUser;
    g_mysqlPasswd   = initInfo.mysqlPasswd;
    g_mysqlDatabase = initInfo.mysqlDatabase;

    std::fstream promptFile("prompt", std::ios::in);
    if (!promptFile.is_open()) {
        return -EIO;
    }
    char buf[65535] {0};
    promptFile.read(buf, sizeof(buf) - 1);
    g_aiPromptTemplate = std::string(buf);
    promptFile.close();

    std::fstream promptFile4Trace("prompt.trace", std::ios::in);
    if (!promptFile4Trace.is_open()) {
        return -EIO;
    }
    char buf4Trace[65535] {0};
    promptFile4Trace.read(buf4Trace, sizeof(buf4Trace) - 1);
    g_aiPromptTemplate4trace = std::string(buf4Trace);
    promptFile4Trace.close();
    return 0;
}

void genResponseReturn(int code, const std::string& message, std::string& response) noexcept {
    response = "{\"code\":" + std::to_string(code) + ",\"message\":\"" + message + "\"}";
}

int checkJsonFormat(const rapidjson::Document& doc, const std::string& memberName, jsonFieldType fieldType, std::string& response) {
    
    if (!doc.HasMember(memberName.c_str())) {
        genResponseReturn(400, "Missing '" + memberName + "' field", response);
        return 400;
    }
    switch (fieldType) {
        case jsonFieldType::IsString:
            if (!doc[memberName.c_str()].IsString()) {
                genResponseReturn(400, "Invalid '" + memberName + "' field, must be a string", response);
                return 400;
            }
            break;
        case jsonFieldType::IsInt64:
            if (!doc[memberName.c_str()].IsInt64()) {
                genResponseReturn(400, "Invalid '" + memberName + "' field, must be a 64-bit integer", response);
                return 400;
            }
            break;
        case jsonFieldType::IsInt:
            if (!doc[memberName.c_str()].IsInt()) {
                genResponseReturn(400, "Invalid '" + memberName + "' field, must be a 32-bit integer", response);
                return 400;
            }
            break;
        case jsonFieldType::IsArray:
            if (!doc[memberName.c_str()].IsArray()) {
                genResponseReturn(400, "Invalid '" + memberName + "' field, must be an array", response);
                return 400;
            }
            break;
        case jsonFieldType::IsObject:
            if (!doc[memberName.c_str()].IsObject()) {
                genResponseReturn(400, "Invalid '" + memberName + "' field, must be an object", response);
                return 400;
            }
            break;
    }
    return 0;

}

// ============================================================================
// RBAC: 检查 token 有效性 + 权限校验
// ============================================================================
int CSystem::checkTokenAndPermission(int64_t user_token, const std::string& permCode, UserSession*& session) {
    this->user_tokens_mutex.lock();
    auto it = user_tokens.find(user_token);
    if (it == user_tokens.end()) {
        this->user_tokens_mutex.unlock();
        return -EINVAL;
    }
    session = it->second.get();
    // admin 角色拥有所有权限
    if (session->role == "admin") {
        this->user_tokens_mutex.unlock();
        return 0;
    }
    // 检查权限
    if (session->permissions.count(permCode) == 0) {
        this->user_tokens_mutex.unlock();
        return -EACCES;
    }
    this->user_tokens_mutex.unlock();
    return 0;
}

// ODBC 连接辅助
static std::string buildOdbcConnStr() {
    return "DRIVER={MariaDB};SERVER=" + g_mysqlHost +
           ";PORT=" + std::to_string(g_mysqlPort) +
           ";DATABASE=" + g_mysqlDatabase +
           ";USER=" + g_mysqlUser +
           ";PASSWORD=" + g_mysqlPasswd + ";";
}

// 辅助：从 MySQL 加载角色权限（ODBC）
static int loadRolePermissions(const std::string& role, std::unordered_set<std::string>& perms) {
    SQLHENV env = SQL_NULL_HANDLE;
    SQLHDBC dbc = SQL_NULL_HANDLE;
    SQLHSTMT stmt = SQL_NULL_HANDLE;
    SQLRETURN ret;
    char permCode[256];

    ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) return -EIO;
    SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);

    ret = SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) { SQLFreeHandle(SQL_HANDLE_ENV, env); return -EIO; }

    std::string connStr = buildOdbcConnStr();
    ret = SQLDriverConnect(dbc, nullptr, (SQLCHAR*)connStr.c_str(), SQL_NTS,
                           nullptr, 0, nullptr, SQL_DRIVER_COMPLETE);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        cerr << "ODBC connect error in loadRolePermissions" << endl;
        SQLFreeHandle(SQL_HANDLE_DBC, dbc); SQLFreeHandle(SQL_HANDLE_ENV, env); return -EIO;
    }

    ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        SQLDisconnect(dbc); SQLFreeHandle(SQL_HANDLE_DBC, dbc); SQLFreeHandle(SQL_HANDLE_ENV, env); return -EIO;
    }

    std::string sql = "SELECT permission_code FROM role_permissions WHERE role = '" + role + "'";
    ret = SQLExecDirect(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
    if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
        while (SQLFetch(stmt) == SQL_SUCCESS) {
            SQLGetData(stmt, 1, SQL_C_CHAR, permCode, sizeof(permCode), nullptr);
            perms.insert(std::string(permCode));
        }
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    SQLFreeHandle(SQL_HANDLE_ENV, env);
    return 0;
}

// 辅助：写审计日志到 MySQL（ODBC）
static void writeAuditLog(int64_t uid, const std::string& username, const std::string& role,
                          const std::string& action, const std::string& resource,
                          const std::string& ip, const std::string& result,
                          const std::string& errorMsg = "") {
    SQLHENV env = SQL_NULL_HANDLE;
    SQLHDBC dbc = SQL_NULL_HANDLE;
    SQLHSTMT stmt = SQL_NULL_HANDLE;
    SQLRETURN ret;

    ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) return;
    SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);

    ret = SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) { SQLFreeHandle(SQL_HANDLE_ENV, env); return; }

    std::string connStr = buildOdbcConnStr();
    ret = SQLDriverConnect(dbc, nullptr, (SQLCHAR*)connStr.c_str(), SQL_NTS,
                           nullptr, 0, nullptr, SQL_DRIVER_COMPLETE);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        SQLFreeHandle(SQL_HANDLE_DBC, dbc); SQLFreeHandle(SQL_HANDLE_ENV, env); return;
    }

    ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        SQLDisconnect(dbc); SQLFreeHandle(SQL_HANDLE_DBC, dbc); SQLFreeHandle(SQL_HANDLE_ENV, env); return;
    }

    std::string sql = "INSERT INTO audit_logs (user_id, username, role, action, resource, request_ip, result, error_msg) "
                      "VALUES (" + std::to_string(uid) + ", '" + username + "', '" + role + "', '" +
                      action + "', '" + resource + "', '" + ip + "', '" + result + "', '" + errorMsg + "')";
    SQLExecDirect(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    SQLFreeHandle(SQL_HANDLE_ENV, env);
}

// ============================================================================
// login: MySQL 验证用户 → 加载权限 → DPFS root 登录 → 缓存 session → 审计日志
// ============================================================================
int CSystem::login(const std::string& request, std::string& response) {

    // get json string
    int rc = 0;
    const std::string& jsonStr = request;

    // create doc and parse json string
    rapidjson::Document doc;
    doc.Parse(jsonStr.c_str());

    // check success
    if (doc.HasParseError()) {
        genResponseReturn(400, std::string(rapidjson::GetParseError_En(doc.GetParseError())), response);
        return 400;
    }

    // check json type
    if (!doc.IsObject()) {
        genResponseReturn(400, "Root must be a JSON object", response);
        return 400;
    }

    // check username and password field
    rc = checkJsonFormat(doc, "username", jsonFieldType::IsString, response); if (rc != 0) { return rc;}
    rc = checkJsonFormat(doc, "password", jsonFieldType::IsString, response); if (rc != 0) { return rc;}

    std::string username = doc["username"].GetString();
    std::string password = doc["password"].GetString();

    // ─── 1. MySQL 验证（ODBC） ───
    int64_t dbUid = 0;
    std::string dbRole;
    std::string dbPasswd;
    std::string dbStatus;
    {
        SQLHENV env = SQL_NULL_HANDLE;
        SQLHDBC dbc = SQL_NULL_HANDLE;
        SQLHSTMT stmt = SQL_NULL_HANDLE;
        SQLRETURN ret;
        char colUid[32], colRole[32], colPasswd[256], colStatus[32];
        SQLLEN ind;

        ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
        if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
            SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
            ret = SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
            if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                std::string connStr = buildOdbcConnStr();
                ret = SQLDriverConnect(dbc, nullptr, (SQLCHAR*)connStr.c_str(), SQL_NTS,
                                       nullptr, 0, nullptr, SQL_DRIVER_COMPLETE);
                if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                    ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
                    if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                        std::string sql = "SELECT id, role, passwd, status FROM users WHERE name = '" + username + "'";
                        ret = SQLExecDirect(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
                        if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                            if (SQLFetch(stmt) == SQL_SUCCESS) {
                                SQLGetData(stmt, 1, SQL_C_CHAR, colUid, sizeof(colUid), &ind);
                                SQLGetData(stmt, 2, SQL_C_CHAR, colRole, sizeof(colRole), &ind);
                                SQLGetData(stmt, 3, SQL_C_CHAR, colPasswd, sizeof(colPasswd), &ind);
                                SQLGetData(stmt, 4, SQL_C_CHAR, colStatus, sizeof(colStatus), &ind);
                                dbUid    = std::stoll(colUid);
                                dbRole   = std::string(colRole);
                                dbPasswd = std::string(colPasswd);
                                dbStatus = std::string(colStatus);
                            } else {
                                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                                SQLDisconnect(dbc);
                                SQLFreeHandle(SQL_HANDLE_DBC, dbc);
                                SQLFreeHandle(SQL_HANDLE_ENV, env);
                                genResponseReturn(403, "Invalid username or password", response);
                                return 403;
                            }
                        }
                        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                    }
                    SQLDisconnect(dbc);
                }
                SQLFreeHandle(SQL_HANDLE_DBC, dbc);
            }
            SQLFreeHandle(SQL_HANDLE_ENV, env);
        }
        if (dbStatus.empty()) {
            cerr << "ODBC login query error" << endl;
            genResponseReturn(500, "Database error", response);
            return 500;
        }
    }

    // 校验密码
    if (dbPasswd != password) {
        writeAuditLog(dbUid, username, dbRole, "login", "/api/login", "",
                      "failure", "Invalid password");
        genResponseReturn(403, "Invalid username or password", response);
        return 403;
    }

    // 校验账户状态
    if (dbStatus == "disabled" || dbStatus == "locked") {
        writeAuditLog(dbUid, username, dbRole, "login", "/api/login", "",
                      "failure", "Account is " + dbStatus);
        genResponseReturn(403, "Account is " + dbStatus, response);
        return 403;
    }

    // ─── 2. 加载权限 ───
    auto session = std::make_shared<UserSession>();
    session->uid      = dbUid;
    session->username = username;
    session->role     = dbRole;
    rc = loadRolePermissions(dbRole, session->permissions);
    if (rc != 0) {
        genResponseReturn(500, "Failed to load permissions", response);
        return 500;
    }

    // ─── 3. DPFS gRPC 连接 + root 登录 ───
    auto channel = grpc::CreateChannel(g_connStr, grpc::InsecureChannelCredentials());
    if (channel == nullptr) {
        cerr << "Failed to create gRPC channel" << endl;
        genResponseReturn(500, "Connect to db error", response);
        return 500;
    }

    this->user_tokens_mutex.lock();
    auto it = user_tokens.emplace(usr_token, session);
    int64_t token = usr_token;
    ++usr_token;
    this->user_tokens_mutex.unlock();

    // 创建 DPFS gRPC 客户端
    session->client = std::make_shared<CGrpcCli>(channel);
    CGrpcCli& client = *session->client;
    rc = client.login("root", "root");
    if (rc != 0) {
        cout << "DPFS login failed for user: " << username << ", error code: " << rc << endl;
        cout << "Error message: \n" << client.msg << endl;
        // 移除失败的 session
        this->user_tokens_mutex.lock();
        user_tokens.erase(token);
        this->user_tokens_mutex.unlock();
        genResponseReturn(500, "DPFS login failed: " + client.msg, response);
        return 500;
    }
    cout << "Login successful for user: " << username << " (role: " << dbRole << ")" << endl;

    // ─── 4. 更新最后登录时间（ODBC） ───
    {
        SQLHENV env = SQL_NULL_HANDLE;
        SQLHDBC dbc = SQL_NULL_HANDLE;
        SQLHSTMT stmt = SQL_NULL_HANDLE;
        SQLRETURN ret;
        ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
        if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
            SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
            ret = SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
            if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                std::string connStr = buildOdbcConnStr();
                ret = SQLDriverConnect(dbc, nullptr, (SQLCHAR*)connStr.c_str(), SQL_NTS,
                                       nullptr, 0, nullptr, SQL_DRIVER_COMPLETE);
                if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                    ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
                    if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                        std::string sql = "UPDATE users SET last_login_at = NOW() WHERE id = " + std::to_string(dbUid);
                        SQLExecDirect(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
                        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                    }
                    SQLDisconnect(dbc);
                }
                SQLFreeHandle(SQL_HANDLE_DBC, dbc);
            }
            SQLFreeHandle(SQL_HANDLE_ENV, env);
        }
    }

    // ─── 5. 审计日志 ───
    writeAuditLog(dbUid, username, dbRole, "login", "/api/login", "", "success");

    // ─── 6. 返回响应 ───
    rapidjson::Document docResponse;
    docResponse.SetObject();
    auto& allocator = docResponse.GetAllocator();
    docResponse.AddMember("code", 0, allocator);
    docResponse.AddMember("message", rapidjson::Value("Login successful"), allocator);
    docResponse.AddMember("user_token", rapidjson::Value(token), allocator);
    docResponse.AddMember("role", rapidjson::Value(dbRole.c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    docResponse.Accept(writer);
    response = buffer.GetString();

    return 0;
}

// ============================================================================
// logout: 审计日志 + 清理 session
// ============================================================================
int CSystem::logout(const std::string& request, std::string& response) {
    int rc = 0;
    const std::string& jsonStr = request;

    // create doc and parse json string
    rapidjson::Document doc;
    doc.Parse(jsonStr.c_str());

    // check success
    if (doc.HasParseError()) {
        genResponseReturn(400, std::string(rapidjson::GetParseError_En(doc.GetParseError())), response);
        return 400;
    }

    // check json type
    if (!doc.IsObject()) {
        genResponseReturn(400, "Root must be a JSON object", response);
        return 400;
    }

    // check user_token field
    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }

    int64_t user_token = doc["user_token"].GetInt64();
    this->user_tokens_mutex.lock();
    auto it = user_tokens.find(user_token);
    if (it == user_tokens.end()) {
        this->user_tokens_mutex.unlock();
        genResponseReturn(400, "Invalid user token", response);
        return 400;
    }
    std::string username = it->second->username;
    std::string role     = it->second->role;
    int64_t uid          = it->second->uid;
    CGrpcCli& client = *it->second->client;
    rc = client.logoff();
    if (rc == 0) {
        genResponseReturn(0, "Logoff successful", response);
        // 审计日志
        writeAuditLog(uid, username, role, "logout", "/api/logout", "", "success");
        user_tokens.erase(it);
    } else {
        genResponseReturn(rc, client.msg, response);
        writeAuditLog(uid, username, role, "logout", "/api/logout", "", "failure", client.msg);
        user_tokens.erase(it);
    }
    this->user_tokens_mutex.unlock();

    return rc;
}

// ============================================================================
// listTracablePro — 需要权限: product:list
// ============================================================================
int CSystem::listTracablePro(const std::string& request, std::string& response) {

    // return message struct
    std::string group_name;      // 组名
    std::string product_name;    // 产品名
    std::string trace_code_prefix; // 溯源编码前缀


    int rc = 0;
    rapidjson::Document doc;
    doc.Parse(request.c_str());

    if (doc.HasParseError()) {
        genResponseReturn(400, std::string(rapidjson::GetParseError_En(doc.GetParseError())), response);
        return 400;
    }

    if (!doc.IsObject()) {
        genResponseReturn(400, "Root must be a JSON object", response);
        return 400;
    }

    if (!doc.IsObject()) {
        genResponseReturn(400, "Root must be a JSON object", response);
        return 400;
    }
    
    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }

    int64_t user_token = doc["user_token"].GetInt64();
    UserSession* session = nullptr;
    rc = checkTokenAndPermission(user_token, "product:list", session);
    if (rc != 0) {
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); }
        else               { genResponseReturn(400, "Invalid user token", response); }
        return 400;
    }
    CGrpcCli& client = *session->client;
    /*
    # Request
parameter                 | type                               | describe  
------------------------- | ---------------------------------- | 
user_token                | Number                             | 
begin                     | Number                             | 提取的起始位置
limit                     | Number                             | 提取的数量
# Response
parameter                 | type                               | describe
------------------------- | ---------------------------------- | ----------------------------------              
code                      | Number                             | 
message                   | String                             | 
total                     | Number                             | 溯源结构总数(全部的数量，不是本次提取的数量)
trace_pros                | Array of Objects                   | 溯源结构列表
    */
    
    rc = checkJsonFormat(doc, "begin", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "limit", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }

    int64_t begin = doc["begin"].GetInt64();
    int64_t limit = doc["limit"].GetInt64();

    rc = client.getTableHandle("SYSDPFS", "SYSTRACEABLES"); 
    if (rc != 0) {
        genResponseReturn(rc, client.msg, response);
        return rc;
    }

    std::vector<std::string> idxCol;
    idxCol.emplace_back();
    idxCol[0].resize(8);
    memcpy(const_cast<char*>(idxCol[0].data()), &begin, sizeof(begin));
    IDXHANDLE hidx = 0;

    rc = client.getIdxIter({"TID"}, idxCol, hidx);
    if (rc != 0) {
        if (rc == ENOENT) {
            genResponseReturn(0, "No more traceable products", response);
            return 0;
        }
        genResponseReturn(rc, client.msg, response);
        return rc;
    }

    rc = client.fetchNextRow(hidx);
    if (rc != 0) {
        if (rc == ENOENT) {
            genResponseReturn(0, "No more traceable products", response);
            return 0;
        }
        genResponseReturn(rc, client.msg, response);
        return rc;
    }

    rapidjson::Document docRet;
    docRet.SetObject();
    auto& allocator = docRet.GetAllocator();

/*
    "ROOT",      dpfs_datatype_t::TYPE_BINARY,    16,
    "NAME",      dpfs_datatype_t::TYPE_CHAR,      64,
    "SCHEMA",    dpfs_datatype_t::TYPE_CHAR,      64,
*/
    size_t total = 0;
    rapidjson::Value traceProArr(rapidjson::kArrayType);
    for (int i = 0; i < limit; ++i) {
        if (rc != 0) {
            break;
        }

        std::string gval;
        rc = client.getDataByIdxIter(hidx, 0, gval);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }
        
        std::string trace_code_prefix = toHexString((uint8_t*)gval.data(), gval.size());

        rc = client.getDataByIdxIter(hidx, 1, gval);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }
        std::string product_name(gval);

        rc = client.getDataByIdxIter(hidx, 2, gval);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }
        std::string group_name(gval);

        /*
        {
            code: 0 ,
            message : "",
            total: 128,
            trace_pros : [
                {"group_name":"北京林业大学",product_name:"苹果派","trace_code_prefix":"00000000000000001D05000000000000"},
                {"group_name":"北京林业大学",product_name:"香蕉派","trace_code_prefix":"00000000000000001D09000000000000"},
                {"group_name":"北京林业大学",product_name:"草莓派","trace_code_prefix":"00000000000000001D01000000000000"}
            ]
        }
        */
        
        rapidjson::Value traceProObj(rapidjson::kObjectType);
        traceProObj.AddMember("group_name", rapidjson::Value(group_name.c_str(), allocator), allocator);
        traceProObj.AddMember("product_name", rapidjson::Value(product_name.c_str(), allocator), allocator);
        traceProObj.AddMember("trace_code_prefix", rapidjson::Value(trace_code_prefix.c_str(), allocator), allocator);
        traceProArr.PushBack(traceProObj, allocator);
        ++total;

        rc = client.fetchNextRow(hidx);
        if (rc != 0) {
            break;
        }
    }

    docRet.AddMember("total", total, allocator);
    docRet.AddMember("trace_pros", traceProArr, allocator);

    rc = client.releaseIdxIter(hidx);
    if (rc != 0) {
    }

    rc = client.releaseTableHandle();
    if (rc != 0) {
        genResponseReturn(rc, client.msg, response);
        return rc;
    }

    docRet.AddMember("code", 200, allocator);
    docRet.AddMember("message", "", allocator);
    
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    docRet.Accept(writer);
    response = buffer.GetString();

    return 0;

}

// ============================================================================
// risk — 需要权限: product:risk:create
// ============================================================================
int CSystem::risk(const std::string& request, std::string& response) {

    int rc = 0;
    const std::string& jsonStr = request;

    rapidjson::Document doc;
    doc.Parse(jsonStr.c_str());

    if (doc.HasParseError()) {
        genResponseReturn(400, std::string(rapidjson::GetParseError_En(doc.GetParseError())), response);
        return 400;
    }

    if (!doc.IsObject()) {
        genResponseReturn(400, "Root must be a JSON object", response);
        return 400;
    }

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "schema", jsonFieldType::IsString, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "product_name", jsonFieldType::IsString, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "product_number", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "ingredients", jsonFieldType::IsArray, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "base_info", jsonFieldType::IsArray, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "risk_report", jsonFieldType::IsInt, response); if (rc != 0) { return rc; }

    std::string schema = doc["schema"].GetString();
    std::string product_name = doc["product_name"].GetString();

    UserSession* session = nullptr;
    rc = checkTokenAndPermission(doc["user_token"].GetInt64(), "product:risk:create", session);
    if (rc != 0) {
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); }
        else               { genResponseReturn(400, "Invalid user token", response); }
        return 400;
    }
    CGrpcCli& client = *session->client;

    // create pro
    std::map<std::string, std::string> ingredients;
    for (const auto& item : doc["ingredients"].GetArray()) {
        if (!item.IsArray() || item.Size() != 2 || !item[0].IsString() || !item[1].IsString()) {
            genResponseReturn(400, "Invalid 'ingredients' field, must be an array of (string, string) pairs", response);
            return 400;
        }

        // name should not same with product_name
        if (strcmp(item[0].GetString(), doc["product_name"].GetString()) == 0) {
            genResponseReturn(400, "Ingredient name should not be same with product name", response);
            return 400;
        }

        ingredients[item[0].GetString()] = item[1].GetString();
    }
    std::map<std::string, std::string> base_info;
    for (const auto& item : doc["base_info"].GetArray()) {
        if (!item.IsArray() || item.Size() != 2 || !item[0].IsString() || !item[1].IsString()) {
            genResponseReturn(400, "Invalid 'base_info' field, must be an array of (string, string) pairs", response);
            return 400;
        }
        base_info[item[0].GetString()] = item[1].GetString();
    }
    int risk_report = doc["risk_report"].GetInt();
    size_t product_number = doc["product_number"].GetInt64();
    std::string trace_code_prefix;
    rc = client.createTracablePro(
        schema,
        product_name,
        base_info,
        ingredients,
        product_number,
        trace_code_prefix
    );
    if (rc != 0) {
        genResponseReturn(rc, client.msg, response);
        return rc;
    }
    
    if (risk_report == 1) {
        std::string trace_code;
        trace_code.resize(20);
        memcpy(trace_code.data(), trace_code_prefix.data(), 16);
        memset(trace_code.data() + 16, 0, 4);
        
        std::string trace_result;
        rc = client.traceBack(trace_code, trace_result, 0);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }

        cout << "trace back result : " << trace_result << endl;

        CGrpcCli::CResult result;
        rc = client.parseTraceResult(trace_result, result);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }

        std::string risk_info;
        rc = this->generateRiskReport(result, risk_info, client);
        if (rc != 0) {
            genResponseReturn(400, client.msg, response);
            return rc;
        }

        rapidjson::Document docRiskInfo;
        docRiskInfo.SetObject();
        docRiskInfo.Parse(risk_info.c_str());
        if (docRiskInfo.HasParseError()) {
            genResponseReturn(400, std::string(rapidjson::GetParseError_En(docRiskInfo.GetParseError())), response);
            return 400;
        }
        std::string risk = docRiskInfo["risk"].GetString();
        std::string health = docRiskInfo["health"].GetString();
        if (memcmp(risk.c_str(), "h", 1) == 0 || memcmp(health.c_str(), "h", 1) == 0) {
            std::string sql = "INSERT INTO SYSDPFS.SYSRISKWARNS VALUES ('" + schema + "', '" + product_name + "', '" + risk_info + "', 0)";
            cout << " insert sql : " << sql << endl;
            rc = client.execSQL(sql);
            if (rc != 0) {
                genResponseReturn(400, client.msg, response);
                return rc;
            }
        }

        rapidjson::Document docRet;
        docRet.SetObject();
        auto& allocator = docRet.GetAllocator();
        docRet.AddMember("code", 200, allocator);
        docRet.AddMember("message", "", allocator);
        docRet.AddMember("risk_info", rapidjson::Value(risk_info.c_str(), allocator), allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        docRet.Accept(writer);
        response = buffer.GetString();
    } else {
        std::string tc = toHexString((uint8_t*)trace_code_prefix.data(), trace_code_prefix.size());
        genResponseReturn(200, "Traceable product created successfully, trace code prefix: " + tc, response);
    }

    cout << response << endl;
    return 0;

}

/*
Ingredient Info:
Ingredient Trace Code: 0000000000000000130500000000000000000000
Ingredient Percentage: 50.00
Ingredient Name: 白糖
-----------------
Ingredient Trace Code: 0000000000000000c40400000000000000000000
Ingredient Percentage: 50.00
Ingredient Name: 食盐
-----------------
*/
// ============================================================================
// recursiveTrace — 递归溯源
// ============================================================================
int CSystem::recursiveTrace(const std::string& trace_code, CGrpcCli& client, std::string& result, std::string indent, void* tDoc, void* parentDoc, double parentProportion, std::map<std::string, double>* metaIngredients) {
    int rc = 0;
    std::string trace_result;
    std::string tc = hex2Binary(trace_code);
    rc = client.traceBack(tc, trace_result, 0);
    if (rc != 0) {
        return rc;
    }
    CGrpcCli::CResult tresult;
    rc = client.parseTraceResult(trace_result, tresult);
    if (rc != 0) {
        return rc;
    }

    auto addMember = [parentDoc](void* tDoc, const std::string& key, const std::string& value) {
        if (tDoc && parentDoc) {
            static_cast<rapidjson::Document*>(tDoc)->AddMember(
                rapidjson::Value(key.c_str(), static_cast<rapidjson::Document*>(parentDoc)->GetAllocator()), 
                rapidjson::Value(value.c_str(), static_cast<rapidjson::Document*>(parentDoc)->GetAllocator()), 
                static_cast<rapidjson::Document*>(parentDoc)->GetAllocator());
        }
    };

    auto addObject = [parentDoc](void* tDoc, const std::string& key, rapidjson::Document& target) {
        if (tDoc && parentDoc) {
            rapidjson::Document& doc = *static_cast<rapidjson::Document*>(tDoc);
            doc.AddMember(
                rapidjson::Value(key.c_str(), static_cast<rapidjson::Document*>(parentDoc)->GetAllocator()), 
                target, 
                static_cast<rapidjson::Document*>(parentDoc)->GetAllocator());
        }
        
    };

    auto printDoc = [](rapidjson::Document& doc){
        rapidjson::StringBuffer bufferTdoc;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writerTd(bufferTdoc);
        doc.Accept(writerTd);
        cout << bufferTdoc.GetString() << endl;
    };

    // base info
    std::string ingredientBaseInfo = "Ingredient Base Info:\n";
    for (const auto& [key, value] : tresult.base_info) {
        if (memcmp(key.c_str(), "ccount", 6) == 0) {
            continue;
        } else if (memcmp(key.c_str(), "cstate", 6) == 0) {
            continue;
        } else if (memcmp(key.c_str(), "ctime", 5) == 0) {
            continue;
        } else if (memcmp(key.c_str(), "uid", 3) == 0) {
            continue;
        }

        ingredientBaseInfo += indent + key + ": " + value + "\n";
        addMember(tDoc, key, value);
    }
    result += ingredientBaseInfo;

    rapidjson::Document ingArrayDoc;
    ingArrayDoc.SetArray();
    
    // for each ingredient, add to array
    for (const auto& ingredient : tresult.ingredient_info) {
        std::string ingredientInfoStr = indent + "Ingredient Info:\n";
        std::string childTraceCode;
        std::string ingredientName;
        double ingredientPercentage = 0.0;

        // for this ingredient, create a json object
        rapidjson::Document ingredientDoc;
        ingredientDoc.SetObject();
        // ingredient base info
        for (const auto& [key, value] : ingredient.ingredient_info) {
            // cout << indent << key << ": " << value << endl;
            if (memcmp(key.c_str(), "Ingredient Trace Code", 21) == 0) {
                childTraceCode = value;
                continue;
            }
            if (memcmp(key.c_str(), "Ingredient Name", 14) == 0) {
                ingredientName = value;
            }
            if (memcmp(key.c_str(), "Ingredient Percentage", 21) == 0) {
                try {
                    ingredientPercentage = std::stod(value);
                } catch (...) {
                    ingredientPercentage = 0.0;
                }
            }
            
            ingredientInfoStr += indent + key + ": " + value + "\n";
            if (tDoc && parentDoc) {
                ingredientDoc.AddMember(
                    rapidjson::Value(key.c_str(), static_cast<rapidjson::Document*>(parentDoc)->GetAllocator()), 
                    rapidjson::Value(value.c_str(), static_cast<rapidjson::Document*>(parentDoc)->GetAllocator()), 
                    static_cast<rapidjson::Document*>(parentDoc)->GetAllocator());
            }
        }

        result += ingredientInfoStr;

        // calculate this ingredient's proportion relative to root
        double currentProportion = parentProportion * (ingredientPercentage / 100.0);

        // 判断溯源码是否全零（全零视为无效/无溯源码，即叶子配料）
        bool traceCodeAllZero = true;
        for (char c : childTraceCode) {
            if (c != '0') { traceCodeAllZero = false; break; }
        }
        bool hasValidTraceCode = !childTraceCode.empty() && !traceCodeAllZero;

        // if has valid (non-zero) child trace code, recursive trace child ingredient
        if (hasValidTraceCode) {
            // result += indent + "Tracing child ingredient with trace code: " + childTraceCode + "\n";
            rapidjson::Document childDoc;
            childDoc.SetObject();
            // cout << "trace back child ingredient with trace code: " << childTraceCode << endl;

            // 记录递归前 metaIngredients 占比总和，用于检测递归后份额丢失
            double beforeSum = 0;
            if (metaIngredients) {
                for (const auto& [n, p] : *metaIngredients) beforeSum += p;
            }

            rc = recursiveTrace(childTraceCode, client, result, indent + "  ", &childDoc, parentDoc, currentProportion, metaIngredients);
            if (rc == 0) {
                addObject(&ingredientDoc, "IngredientInfo", childDoc);

                // 检查递归后实际收集的元配料占比是否等于预期
                if (metaIngredients && !ingredientName.empty()) {
                    double afterSum = 0;
                    for (const auto& [n, p] : *metaIngredients) afterSum += p;
                    double collected = afterSum - beforeSum;
                    if (collected < currentProportion - 1e-9) {
                        // 递归成功但份额有丢失（子配料被过滤/乱码），差额归入当前配料名
                        (*metaIngredients)[ingredientName] += (currentProportion - collected);
                    }
                }
            } else {
                // 递归失败，配料无法继续溯源，作为元配料收集
                if (metaIngredients && !ingredientName.empty()) {
                    (*metaIngredients)[ingredientName] += currentProportion;
                }
            }
        } else {
            // leaf ingredient (元配料/基础配料): no valid trace code available
            if (metaIngredients && !ingredientName.empty()) {
                (*metaIngredients)[ingredientName] += currentProportion;
            }
        }
        
        if (tDoc && parentDoc) {
            ingArrayDoc.PushBack(ingredientDoc, static_cast<rapidjson::Document*>(parentDoc)->GetAllocator());
        }
    }
    
    addObject(tDoc, "IngredientInfo", ingArrayDoc);

    return 0;
}

// ============================================================================
// generateRiskReport — 生成风险评估报告（待优化，使用内置模型）
// ============================================================================
int CSystem::generateRiskReport(const CGrpcCli::CResult& result, std::string& risk_info, CGrpcCli& client) {
    const std::string& apiKey = g_apiKey;
    DeepSeekClient dclient(apiKey);
    std::string userInput;

    std::string baseInfoStr = "Base Info:\n";
    for (const auto& [key, value] : result.base_info) {
        if (memcmp(key.c_str(), "ccount", 6) == 0) {
            continue;
        } else if (memcmp(key.c_str(), "cstate", 6) == 0) {
            continue;
        } else if (memcmp(key.c_str(), "ctime", 5) == 0) {
            continue;
        } else if (memcmp(key.c_str(), "uid", 3) == 0) {
            continue;
        }
        baseInfoStr += key + ": " + value + "\n";
    }
    std::vector<std::string> recursiveTraceCodes;
    recursiveTraceCodes.reserve(result.ingredient_info.size());

    std::string ingredientInfoStr = "Ingredient Info:\n";
    for (const auto& ingredient : result.ingredient_info) {
        for (const auto& [key, value] : ingredient.ingredient_info) {
/*
ignore:
 ccount/校验次数: 1
 cstate/校验状态: 1
 ctime/上一次校验时间: 1774603209
 uid/产品编号: 0
*/
            if (memcmp(key.c_str(), "Ingredient Trace Code", 21) == 0) {
                recursiveTraceCodes.emplace_back(value);
                continue;
            }
            ingredientInfoStr += key + ": " + value + "\n";
        }
        cout << "recursive tracing this ingredient..." << endl;
        ingredientInfoStr += "child ingredient trace result: {\n";
        int rc = recursiveTrace(recursiveTraceCodes.back(), client, ingredientInfoStr, " ");
        if (rc != 0) {
        }
        ingredientInfoStr += "}\n";
        
        ingredientInfoStr += "-----------------\n";
    }

    
    cout << baseInfoStr << endl;
    cout << ingredientInfoStr << endl;

    // 输入提示词，输出风险评估报告
    
    userInput += g_aiPromptTemplate;
    userInput += baseInfoStr + "\n" + ingredientInfoStr + "\n";

    // cout << "User input: " << userInput << endl;
    risk_info = dclient.Chat(userInput);

    cout << risk_info << endl;
    // risk_info = "This is a mock risk report generated based on the trace result. You can replace this with actual logic to analyze the trace result and generate a meaningful risk report.";
    return 0;
}

// ============================================================================
// traceBack — 需要权限: product:trace
// ============================================================================
int CSystem::traceBack(const std::string& request, std::string& response) {
    
    int rc = 0;
    const std::string& jsonStr = request;

    rapidjson::Document doc;
    doc.Parse(jsonStr.c_str());

    if (doc.HasParseError()) {
        genResponseReturn(400, std::string(rapidjson::GetParseError_En(doc.GetParseError())), response);
        return 400;
    }

    if (!doc.IsObject()) {
        genResponseReturn(400, "Root must be a JSON object", response);
        return 400;
    }

    int64_t trace_defail = 0;
    int64_t ingDet = 0;
    int64_t aiRisk = 0;

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "trace_code", jsonFieldType::IsString, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "trace_detail", jsonFieldType::IsInt64, response); if (rc == 0) { trace_defail = doc["trace_detail"].GetInt64(); }
    rc = checkJsonFormat(doc, "ingre_detail", jsonFieldType::IsInt64, response); if (rc == 0) { ingDet = doc["ingre_detail"].GetInt64(); }
    rc = checkJsonFormat(doc, "ai_risk", jsonFieldType::IsInt64, response); if (rc == 0) { aiRisk = doc["ai_risk"].GetInt64(); }

    rapidjson::Document tDoc;
    tDoc.SetObject();

    auto printDoc = [](rapidjson::Document& doc){
        rapidjson::StringBuffer bufferTdoc;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writerTd(bufferTdoc);
        doc.Accept(writerTd);
        cout << bufferTdoc.GetString() << endl;
    };

    UserSession* session = nullptr;
    rc = checkTokenAndPermission(doc["user_token"].GetInt64(), "product:trace", session);
    if (rc != 0) {
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); }
        else               { genResponseReturn(400, "Invalid user token", response); }
        return 400;
    }
    CGrpcCli& client = *session->client;

    std::string tc = hex2Binary(doc["trace_code"].GetString());
    if (tc.size() != 20) {
        genResponseReturn(400, "Invalid trace code, must be 40 hex characters representing 20 bytes", response);
        return 400;
    }

    std::string trace_result;
    cout << "show detail : " << (bool)trace_defail << endl;
    rc = client.traceBack(tc, trace_result, trace_defail == 0 ? false : true);
    if (rc != 0) {
        genResponseReturn(rc, client.msg, response);
        return rc;
    }
    cout << "trace back result : " << trace_result << endl;

    CGrpcCli::CResult tresult;
    rc = client.parseTraceResult(trace_result, tresult);
    if (rc != 0) {
        genResponseReturn(rc, client.msg, response);
        return rc;
    }    
    std::string aiRiskStr = "";
    aiRiskStr.reserve(1024);
    std::vector<std::string> recursiveTraceCodes;
    recursiveTraceCodes.reserve(tresult.ingredient_info.size());

    std::string traceBaseResult = "Base Info: {\n";
    traceBaseResult.reserve(512);
    for (const auto& [key, value] : tresult.base_info) {
        if (memcmp(key.c_str(), "ctime", 5) == 0) {
            time_t timestamp = std::stoll(value);
            struct tm* timeinfo = localtime(&timestamp);
            char buffer[80];
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
            traceBaseResult += key + ": " + std::string(buffer) + "\n";
            tDoc.AddMember(rapidjson::Value(key.c_str(), tDoc.GetAllocator()), rapidjson::Value(buffer, tDoc.GetAllocator()), tDoc.GetAllocator());
            continue;
        }
        traceBaseResult += key + ": " + value + "\n";
        tDoc.AddMember(rapidjson::Value(key.c_str(), tDoc.GetAllocator()), rapidjson::Value(value.c_str(), tDoc.GetAllocator()), tDoc.GetAllocator());

    }
    
    traceBaseResult += "}\n";

    std::string traceTradeInfo = "Trade Info: {\n";
    traceTradeInfo.reserve(2048);

    rapidjson::Document TradeArrayDoc;
    TradeArrayDoc.SetArray();
    for (const auto& trade : tresult.trade_info) {
        rapidjson::Document tradeDoc;
        tradeDoc.SetObject();
        for (const auto& [key, value] : trade.trade_info) {
            cout << "add trade info: " << key << ": " << value << endl;
            traceTradeInfo += "\"" + key + "\": " + value + "\n";
            tradeDoc.AddMember(rapidjson::Value(key.c_str(), TradeArrayDoc.GetAllocator()), rapidjson::Value(value.c_str(), TradeArrayDoc.GetAllocator()), TradeArrayDoc.GetAllocator());
        }
        traceTradeInfo += "-----------------\n";
        TradeArrayDoc.PushBack(tradeDoc, TradeArrayDoc.GetAllocator());
    }
    tDoc.AddMember("trade_info", TradeArrayDoc, tDoc.GetAllocator());
    
    traceTradeInfo += "}\n";

    // 元配料整合表：存储叶子配料及其相对根产品的累计占比
    std::map<std::string, double> metaIngredients;

    std::string ingredientInfoStr = "Ingredient Info: {\n";
    ingredientInfoStr.reserve(1024);

    rapidjson::Document ingredientArrayDoc;
    ingredientArrayDoc.SetArray();
    
    for (const auto& ingredient : tresult.ingredient_info) {
        rapidjson::Document ingredientDoc;
        ingredientDoc.SetObject();
        std::string childTraceCode;
        std::string firstLevelIngName;
        double firstLevelIngPct = 0.0;
        for (const auto& [key, value] : ingredient.ingredient_info) {
            if (memcmp(key.c_str(), "Ingredient Trace Code", 21) == 0) {
                childTraceCode = value;
                recursiveTraceCodes.emplace_back(value);
                continue;
            }
            if (memcmp(key.c_str(), "Ingredient Name", 14) == 0) {
                firstLevelIngName = value;
            }
            if (memcmp(key.c_str(), "Ingredient Percentage", 21) == 0) {
                try {
                    firstLevelIngPct = std::stod(value);
                } catch (...) {
                    firstLevelIngPct = 0.0;
                }
            }
            ingredientInfoStr += key + ": " + value + "\n";
            ingredientDoc.AddMember(
                rapidjson::Value(key.c_str(), tDoc.GetAllocator()),
                rapidjson::Value(value.c_str(), tDoc.GetAllocator()),
                tDoc.GetAllocator()
            );
        }
        // 判断溯源码是否全零（全零视为无效/无溯源码，即叶子配料）
        bool traceCodeAllZero = true;
        for (char c : childTraceCode) {
            if (c != '0') { traceCodeAllZero = false; break; }
        }
        bool hasValidTraceCode = !childTraceCode.empty() && !traceCodeAllZero;

        if (ingDet == 1 && hasValidTraceCode) {
            // 请求递归展开且有有效溯源码：递归溯源子配料
            ingredientInfoStr += "child ingredient trace result: {\n";
            rapidjson::Document childDoc;
            childDoc.SetObject();
            double childProportion = 1.0 * (firstLevelIngPct / 100.0);

            // 记录递归前 metaIngredients 占比总和，用于检测递归后份额丢失
            double beforeSum = 0;
            for (const auto& [n, p] : metaIngredients) beforeSum += p;

            int rc = recursiveTrace(childTraceCode, client, ingredientInfoStr, " ", &childDoc, &tDoc, childProportion, &metaIngredients);
            if (rc != 0) {
                // 递归失败（子溯源码无效/不可溯），将该配料本身作为"无法继续溯源"的叶子收集
                if (!firstLevelIngName.empty()) {
                    metaIngredients[firstLevelIngName] += childProportion;
                }
            } else {
                // 递归成功，检查实际收集的元配料占比是否等于预期
                if (!firstLevelIngName.empty()) {
                    double afterSum = 0;
                    for (const auto& [n, p] : metaIngredients) afterSum += p;
                    double collected = afterSum - beforeSum;
                    if (collected < childProportion - 1e-9) {
                        // 递归成功但份额有丢失（子配料被过滤/乱码），差额归入当前配料名
                        metaIngredients[firstLevelIngName] += (childProportion - collected);
                    }
                }
            }
            ingredientInfoStr += "}\n";
            ingredientDoc.AddMember(rapidjson::Value("IngredientInfo", tDoc.GetAllocator()), childDoc, tDoc.GetAllocator());
        } else if (!firstLevelIngName.empty()) {
            // 不递归展开(ingDet==0) 或 溯源码无效/全零：该配料作为当前层级的叶子（元配料）收集
            metaIngredients[firstLevelIngName] += firstLevelIngPct / 100.0;
        }
        
        ingredientInfoStr += "-----------------\n";
        ingredientArrayDoc.PushBack(ingredientDoc, tDoc.GetAllocator());
    }
    tDoc.AddMember("ingredient_info", ingredientArrayDoc, tDoc.GetAllocator());
    ingredientInfoStr += "}\n";

    // 解析根产品总克数，从 base_info 中查找重量字段
    double totalGrams = 0.0;
    for (const auto& [key, value] : tresult.base_info) {
        std::string keyLower = key;
        // 转小写用于匹配
        for (auto& c : keyLower) { c = std::tolower(c); }
        if (keyLower.find("净含量") != std::string::npos ||
            keyLower.find("重量") != std::string::npos ||
            keyLower.find("净重") != std::string::npos ||
            keyLower.find("规格") != std::string::npos) {
            // 尝试从 value 中提取数字
            try {
                std::string valNum;
                for (char c : value) {
                    if (std::isdigit(c) || c == '.' || c == '-') {
                        valNum += c;
                    }
                }
                if (!valNum.empty()) {
                    double grams = std::stod(valNum);
                    // 如果 value 中包含 "kg" 或 "千克"，转换为克
                    std::string valLower = value;
                    for (auto& c : valLower) { c = std::tolower(c); }
                    if (valLower.find("kg") != std::string::npos ||
                        valLower.find("千克") != std::string::npos) {
                        grams *= 1000.0;
                    }
                    totalGrams = grams;
                }
            } catch (...) {
                totalGrams = 0.0;
            }
            if (totalGrams > 0.0) break;
        }
    }

    if (aiRisk == 1) {
        const std::string& apiKey = g_apiKey;
        DeepSeekClient dclient(apiKey);
        std::string userInput;
        userInput += g_aiPromptTemplate4trace;
        userInput += traceBaseResult + "\n" + traceTradeInfo + "\n" + ingredientInfoStr + "\n";
        aiRiskStr = dclient.Chat(userInput);
    }

    rapidjson::StringBuffer tbuffer;
    rapidjson::Writer<rapidjson::StringBuffer> twriter(tbuffer);
    tDoc.Accept(twriter);
    std::string tDocStr = tbuffer.GetString();


    // 构建元配料整合表 JSON（过滤占比为0或克数为0的无效条目）
    rapidjson::Document metaTableArr;
    metaTableArr.SetArray();
    for (const auto& [name, cumulativePct] : metaIngredients) {
        // 过滤：累计占比为0 或 克数为0 的条目（通常为底层数据异常导致的乱码配料）
        double grams = totalGrams * cumulativePct;
        if (cumulativePct <= 0.0 || grams <= 0.0) {
            continue;
        }

        rapidjson::Document metaItem;
        metaItem.SetObject();
        metaItem.AddMember("name", rapidjson::Value(name.c_str(), metaTableArr.GetAllocator()), metaTableArr.GetAllocator());

        // 百分比格式化
        char pctBuf[32];
        snprintf(pctBuf, sizeof(pctBuf), "%.2f%%", cumulativePct * 100.0);
        metaItem.AddMember("percentage", rapidjson::Value(pctBuf, metaTableArr.GetAllocator()), metaTableArr.GetAllocator());

        // 克数
        char gramBuf[32];
        snprintf(gramBuf, sizeof(gramBuf), "%.2f", grams);
        metaItem.AddMember("grams", rapidjson::Value(gramBuf, metaTableArr.GetAllocator()), metaTableArr.GetAllocator());

        metaTableArr.PushBack(metaItem, metaTableArr.GetAllocator());
    }

    rapidjson::Document retDoc;
    retDoc.SetObject();
    auto& allocator = retDoc.GetAllocator();
    retDoc.AddMember("code", 200, allocator);
    retDoc.AddMember("message", "", allocator);
    retDoc.AddMember("trace_result", rapidjson::Value(tDocStr.c_str(), allocator), allocator);
    retDoc.AddMember("ai_risk_report", rapidjson::Value(aiRiskStr.c_str(), allocator), allocator);
    retDoc.AddMember("meta_ingredient_table", metaTableArr, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    retDoc.Accept(writer);
    response = buffer.GetString();

    return 0;
}

// ============================================================================
// listProBasic — 需要权限: product:list
// ============================================================================
int CSystem::listProBasic(const std::string& request, std::string& response) {

    int rc = 0;
    const std::string& jsonStr = request;

    rapidjson::Document doc;
    doc.Parse(jsonStr.c_str());
    rapidjson::Document retDoc;
    retDoc.SetObject();

    if (doc.HasParseError()) {
        genResponseReturn(400, std::string(rapidjson::GetParseError_En(doc.GetParseError())), response);
        return 400;
    }

    if (!doc.IsObject()) {
        genResponseReturn(400, "Root must be a JSON object", response);
        return 400;
    }

    std::string schema = "";
    std::string name = "";

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "schema", jsonFieldType::IsString, response); if (rc == 0) { schema = doc["schema"].GetString(); }
    rc = checkJsonFormat(doc, "name", jsonFieldType::IsString, response); if (rc == 0) { name = doc["name"].GetString(); }

    UserSession* session = nullptr;
    rc = checkTokenAndPermission(doc["user_token"].GetInt64(), "product:list", session);
    if (rc != 0) {
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); }
        else               { genResponseReturn(400, "Invalid user token", response); }
        return 400;
    }
    CGrpcCli& client = *session->client;

    std::string spxxb = name + "_SPXXB";
    rc = client.getTableHandle(schema, spxxb);
    if (rc != 0) {
        genResponseReturn(rc, client.msg, response);
        return rc;
    }
    
    int32_t hidx = 0;
    std::vector<std::string> idxNames;
    rc = client.getIdxIter(idxNames, {}, hidx);
    if (rc != 0) {
        genResponseReturn(rc, client.msg, response);
        return rc;
    }


    rapidjson::Document basicInfoArrDoc;
    basicInfoArrDoc.SetArray();
    while (client.fetchNextRow(hidx) == 0) {
        rapidjson::Document basicInfoObj;
        basicInfoObj.SetObject();

        std::string oval = "";
        rc = client.getDataByIdxIter(hidx, 0, oval, dpfs_ctype_t::TYPE_STRING);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }
        if (memcmp(oval.c_str(), "SPKZB", 5) == 0 || 
            memcmp(oval.c_str(), "PLKZB", 5) == 0 ||
            memcmp(oval.c_str(), "SPJYB", 5) == 0) {
            continue;
        }
        basicInfoObj.AddMember("key", rapidjson::Value(oval.c_str(), basicInfoArrDoc.GetAllocator()), basicInfoArrDoc.GetAllocator());

        rc = client.getDataByIdxIter(hidx, 1, oval, dpfs_ctype_t::TYPE_STRING);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }
        cout << "value: " << oval << endl;
        basicInfoObj.AddMember("value", rapidjson::Value(oval.c_str(), basicInfoArrDoc.GetAllocator()), basicInfoArrDoc.GetAllocator());

        basicInfoArrDoc.PushBack(basicInfoObj, basicInfoArrDoc.GetAllocator());
    }

    client.releaseIdxIter(hidx);
    client.releaseTableHandle();

    std::string plkzb = name + "_PLKZB";
    rc = client.getTableHandle(schema, plkzb);
    bool hasIngredients = (rc == 0);
    if (rc != 0) {
        cout << "No ingredient table for product: " << name << ", returning empty ingredient_info." << endl;
    }

    rapidjson::Document ingreInfoArrDoc;
    ingreInfoArrDoc.SetArray();

    if (hasIngredients) {
        hidx = 0;
        idxNames.clear();
        rc = client.getIdxIter(idxNames, {}, hidx);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }

        const auto& colInfo = client.getColInfo(hidx);
        cerr << "[DEBUG listProBasic] PLKZB colInfo size=" << colInfo.size() << endl;

        int ingreFetchCount = 0;
        while (client.fetchNextRow(hidx) == 0) {
            ingreFetchCount++;

            rapidjson::Document ingInfoObj;
            ingInfoObj.SetObject();

            std::string oval = "";
            rc = client.getDataByIdxIter(hidx, 0, oval);
            if (rc != 0) {
                genResponseReturn(rc, client.msg, response);
                return rc;
            }

            // 跳过无效配料行：配料名首字节为0说明是脏行（纯二进制内存数据）
            if (oval.empty() || oval[0] == '\0') {
                cout << "Skipping invalid ingredient row #" << ingreFetchCount << " (null name)" << endl;
                continue;
            }

            ingInfoObj.AddMember("ingre_name", rapidjson::Value(oval.c_str(), ingreInfoArrDoc.GetAllocator()), ingreInfoArrDoc.GetAllocator());

            rc = client.getDataByIdxIter(hidx, 1, oval);
            if (rc != 0) {
                genResponseReturn(rc, client.msg, response);
                return rc;
            }
            std::string trace_code_prefix = toHexString((uint8_t*)oval.data(), oval.size());
            ingInfoObj.AddMember("trace_code_prefix", rapidjson::Value(trace_code_prefix.c_str(), ingreInfoArrDoc.GetAllocator()), ingreInfoArrDoc.GetAllocator());

            rc = client.getDataByIdxIter(hidx, 2, oval);
            if (rc != 0) {
                genResponseReturn(rc, client.msg, response);
                return rc;
            }

            {
                my_decimal dec;
                rc = binary2my_decimal(0, (const uchar*)oval.data(), &dec, colInfo[2].getDds().genLen, colInfo[2].getScale());
                if (rc != 0) {
                    cout << "Skipping ingredient row #" << ingreFetchCount << ": decimal conversion failed, rc=" << rc << endl;
                    continue;
                }
                String decStr;
                rc = my_decimal2string(0, &dec, &decStr);
                if (rc != 0) {
                    cout << "Skipping ingredient row #" << ingreFetchCount << ": decimal-to-string failed, rc=" << rc << endl;
                    continue;
                }
                ingInfoObj.AddMember("percentage", rapidjson::Value(decStr.ptr(), ingreInfoArrDoc.GetAllocator()), ingreInfoArrDoc.GetAllocator());
            }

            ingreInfoArrDoc.PushBack(ingInfoObj, ingreInfoArrDoc.GetAllocator());
        }
        client.releaseIdxIter(hidx);
    }

    retDoc.AddMember("code", 200, retDoc.GetAllocator());
    retDoc.AddMember("message", "", retDoc.GetAllocator());
    retDoc.AddMember("basic_info", basicInfoArrDoc, retDoc.GetAllocator());
    retDoc.AddMember("ingredient_info", ingreInfoArrDoc, retDoc.GetAllocator());

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    retDoc.Accept(writer);
    response = buffer.GetString();

    return 0;
}

// ============================================================================
// makeTrade — 需要权限: trade:create
// ============================================================================
int CSystem::makeTrade(const std::string& request, std::string& response) {

    int rc = 0;
    const std::string& jsonStr = request;

    rapidjson::Document doc;
    doc.Parse(jsonStr.c_str());

    if (doc.HasParseError()) {
        genResponseReturn(400, std::string(rapidjson::GetParseError_En(doc.GetParseError())), response);
        return 400;
    }

    if (!doc.IsObject()) {
        genResponseReturn(400, "Root must be a JSON object", response);
        return 400;
    }

    std::string tradeSchema = "";
    std::string tradeProductName = "";
    int64_t tradeProductStartID = 0;
    int64_t tradeProductNumber = 0;
    std::string buyer = "";
    std::string buyerAddr = "";
    std::string buyerPhone = "";
    std::string seller = "";
    std::string sellerAddr = "";
    std::string sellerPhone = "";
    std::string logisticsInfo = "";
    std::string otherInfo = "";
    std::string tradePrice = "";

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "trade_schema", jsonFieldType::IsString, response); if (rc == 0) { tradeSchema = doc["trade_schema"].GetString(); }
    rc = checkJsonFormat(doc, "trade_product_name", jsonFieldType::IsString, response); if (rc == 0) { tradeProductName = doc["trade_product_name"].GetString(); }
    rc = checkJsonFormat(doc, "trade_product_start_id", jsonFieldType::IsInt64, response); if (rc == 0) { tradeProductStartID = doc["trade_product_start_id"].GetInt64(); }
    rc = checkJsonFormat(doc, "trade_product_number", jsonFieldType::IsInt64, response); if (rc == 0) { tradeProductNumber = doc["trade_product_number"].GetInt64(); }
    rc = checkJsonFormat(doc, "buyer", jsonFieldType::IsString, response); if (rc == 0) { buyer = doc["buyer"].GetString(); }
    rc = checkJsonFormat(doc, "buyer_addr", jsonFieldType::IsString, response); if (rc == 0) { buyerAddr = doc["buyer_addr"].GetString(); }
    rc = checkJsonFormat(doc, "buyer_phone", jsonFieldType::IsString, response); if (rc == 0) { buyerPhone = doc["buyer_phone"].GetString(); }
    rc = checkJsonFormat(doc, "seller", jsonFieldType::IsString, response); if (rc == 0) { seller = doc["seller"].GetString(); }
    rc = checkJsonFormat(doc, "seller_addr", jsonFieldType::IsString, response); if (rc == 0) { sellerAddr = doc["seller_addr"].GetString(); }
    rc = checkJsonFormat(doc, "seller_phone", jsonFieldType::IsString, response); if (rc == 0) { sellerPhone = doc["seller_phone"].GetString(); }
    rc = checkJsonFormat(doc, "logistics_info", jsonFieldType::IsString, response); if (rc == 0) { logisticsInfo = doc["logistics_info"].GetString(); }
    rc = checkJsonFormat(doc, "other_info", jsonFieldType::IsString, response); if (rc == 0) { otherInfo = doc["other_info"].GetString(); }
    rc = checkJsonFormat(doc, "trade_price", jsonFieldType::IsString, response); if (rc == 0) { tradePrice = doc["trade_price"].GetString(); }

    if ( tradeSchema == "" || tradeProductName == "") {
        genResponseReturn(400, "Invalid Param", response);
        return 400;
    }

    if (buyer == "")            { genResponseReturn(400, "Invalid Param", response); return 400; };
    if (buyerAddr == "")        { genResponseReturn(400, "Invalid Param", response); return 400; };
    if (buyerPhone == "")       { genResponseReturn(400, "Invalid Param", response); return 400; };
    if (seller == "")           { genResponseReturn(400, "Invalid Param", response); return 400; };
    if (sellerAddr == "")       { genResponseReturn(400, "Invalid Param", response); return 400; };
    if (sellerPhone == "")      { genResponseReturn(400, "Invalid Param", response); return 400; };
    if (logisticsInfo == "")    { genResponseReturn(400, "Invalid Param", response); return 400; };
    if (otherInfo == "")        { genResponseReturn(400, "Invalid Param", response); return 400; };
    if (tradePrice == "")       { genResponseReturn(400, "Invalid Param", response); return 400; };

    UserSession* session = nullptr;
    rc = checkTokenAndPermission(doc["user_token"].GetInt64(), "trade:create", session);
    if (rc != 0) {
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); }
        else               { genResponseReturn(400, "Invalid user token", response); }
        return 400;
    }
    CGrpcCli& client = *session->client;

    rc = client.makeTrade(tradeSchema, tradeProductName, 999/*deprecated*/, tradeProductStartID, tradeProductNumber, buyer, buyerAddr, buyerPhone, seller, sellerAddr, sellerPhone, logisticsInfo, otherInfo, tradePrice);
    if (rc != 0) {
        cout << "Make trade failed, error code: " << rc << endl;
        cout << "Error message: " << client.msg << endl;
        genResponseReturn(400, client.msg, response);
    } else {
        genResponseReturn(200, client.msg, response);
    }
    
    return 0;
}

// ============================================================================
// listRiskPro — 需要权限: product:risk:view
// ============================================================================
int CSystem::listRiskPro(const std::string& request, std::string& response) {


    // return message struct
    std::string group_name;      // 组名
    std::string product_name;    // 产品名
    std::string risk_info; // 风险信息


    int rc = 0;
    rapidjson::Document doc;
    doc.Parse(request.c_str());

    if (doc.HasParseError()) {
        genResponseReturn(400, std::string(rapidjson::GetParseError_En(doc.GetParseError())), response);
        return 400;
    }

    if (!doc.IsObject()) {
        genResponseReturn(400, "Root must be a JSON object", response);
        return 400;
    }

    if (!doc.IsObject()) {
        genResponseReturn(400, "Root must be a JSON object", response);
        return 400;
    }
    
    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }

    int64_t user_token = doc["user_token"].GetInt64();
    UserSession* session = nullptr;
    rc = checkTokenAndPermission(user_token, "product:risk:view", session);
    if (rc != 0) {
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); }
        else               { genResponseReturn(400, "Invalid user token", response); }
        return 400;
    }
    CGrpcCli& client = *session->client;
    /*
    # Request
parameter                 | type                               | describe  
------------------------- | ---------------------------------- | 
user_token                | Number                             | 
begin                     | Number                             | 提取的起始位置
limit                     | Number                             | 提取的数量
# Response
parameter                 | type                               | describe
------------------------- | ---------------------------------- | ----------------------------------              
code                      | Number                             | 
message                   | String                             | 
total                     | Number                             | 溯源结构总数(全部的数量，不是本次提取的数量)
trace_pros                | Array of Objects                   | 溯源结构列表
    */

    rc = checkJsonFormat(doc, "begin", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "limit", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }

    int64_t begin = doc["begin"].GetInt64();
    int64_t limit = doc["limit"].GetInt64();

    rc = client.getTableHandle("SYSDPFS", "SYSRISKWARNS"); 
    if (rc != 0) {
        genResponseReturn(rc, client.msg, response);
        return rc;
    }

    std::vector<std::string> idxCol;
    idxCol.emplace_back();
    idxCol[0].resize(8);
    memcpy(const_cast<char*>(idxCol[0].data()), &begin, sizeof(begin));
    IDXHANDLE hidx = 0;

    rc = client.getIdxIter({"RTID"}, idxCol, hidx);
    if (rc != 0) {
        if (rc == ENOENT) {
            genResponseReturn(0, "No more traceable products", response);
            return 0;
        }
        genResponseReturn(rc, client.msg, response);
        return rc;
    }

    size_t total = 0; (void)client.getColInfo(hidx);

    rc = client.fetchNextRow(hidx);
    if (rc != 0) {
        if (rc == ENOENT) {
            genResponseReturn(0, "No more traceable products", response);
            return 0;
        }
        genResponseReturn(rc, client.msg, response);
        return rc;
    }

    rapidjson::Document docRet;
    docRet.SetObject();
    auto& allocator = docRet.GetAllocator();

    rapidjson::Document traceProArr;
    traceProArr.SetArray();
    for (int i = 0; i < limit; ++i) {
        if (rc != 0) {
            break;
        }
        rapidjson::Document traceProObj;
        traceProObj.SetObject();

        std::string gval;
        rc = client.getDataByIdxIter(hidx, 0, gval);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }
        
        std::string schema(gval);

        rc = client.getDataByIdxIter(hidx, 1, gval);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }
        std::string product_name(gval);

        rc = client.getDataByIdxIter(hidx, 2, gval);
        if (rc != 0) {
            genResponseReturn(rc, client.msg, response);
            return rc;
        }
        std::string describe(gval);
        
        /*
        {
            code: 0 ,
            message : "",
            total: 128,
            trace_pros : [
                {"schema":"OOO", "product_name":"苹果派", "risk_description":"风险描述1"},
                {"schema":"OOO", "product_name":"香蕉派", "risk_description":"风险描述2"},
                {"schema":"OOO", "product_name":"草莓派", "risk_description":"风险描述3"}
            ]
        }
        */

        traceProObj.AddMember("schema", rapidjson::Value(schema.c_str(), allocator), allocator);
        traceProObj.AddMember("product_name", rapidjson::Value(product_name.c_str(), allocator), allocator);
        traceProObj.AddMember("risk_description", rapidjson::Value(describe.c_str(), allocator), allocator);
        
        traceProArr.PushBack(traceProObj, allocator);
        ++total;

        rc = client.fetchNextRow(hidx);
        if (rc != 0) {
            break;
        }
    }

    docRet.AddMember("total", total, allocator);
    docRet.AddMember("pro_list", traceProArr, allocator);

    rc = client.releaseIdxIter(hidx);
    if (rc != 0) {
    }

    rc = client.releaseTableHandle();
    if (rc != 0) {
        genResponseReturn(rc, client.msg, response);
        return rc;
    }

    docRet.AddMember("code", 200, allocator);
    docRet.AddMember("message", "", allocator);
    
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    docRet.Accept(writer);
    response = buffer.GetString();

    return 0;
}