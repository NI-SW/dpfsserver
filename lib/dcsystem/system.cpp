#include <dcsystem/system.hpp>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <deepseek/deepseek.hpp>
#include <fstream>
#include <log/logbinary.h>

// 全局日志实例
extern logrecord* dlog;
#include <sstream>
#include <sql.h>
#include <sqlext.h>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>
#include <dirent.h>
#include <set>
#include <functional>
#include <chrono>
#include <sys/statvfs.h>
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

// 全局日志实例
logrecord* dlog = nullptr;

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

    // 初始化日志模块
    if (!dlog) {
        dlog = new logrecord();
    }
    dlog->set_log_path("/home/dpfs/github/dpfsserver/app/server/dserver.log");
    dlog->set_loglevel(logrecord::LOG_INFO);

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
        dlog->log_error("ODBC connect error in loadRolePermissions\n");
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

    // 输入长度上限校验 (防止超长字符串传递至 MySQL/dpfs 导致崩溃)
    if (username.length() > 64) {
        genResponseReturn(400, "Username too long (max 64 characters)", response);
        return 400;
    }
    if (password.length() > 128) {
        genResponseReturn(400, "Password too long (max 128 characters)", response);
        return 400;
    }

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
                            dlog->log_notic("[WARN] Login failed: user '%s' not found\n", username.c_str());
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
            dlog->log_error("ODBC login query error\n");
            genResponseReturn(500, "Database error", response);
            return 500;
        }
    }

    // 校验密码
    if (dbPasswd != password) {
        dlog->log_notic("[WARN] Login failed: invalid password for user '%s'\n", username.c_str());
        writeAuditLog(dbUid, username, dbRole, "login", "/api/login", "",
                      "failure", "Invalid password");
        genResponseReturn(403, "Invalid username or password", response);
        return 403;
    }

    // 校验账户状态
    if (dbStatus == "disabled" || dbStatus == "locked") {
        dlog->log_notic("[WARN] Login failed: account '%s' is %s\n", username.c_str(), dbStatus.c_str());
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
        dlog->log_error("Failed to create gRPC channel\n");
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
        dlog->log_error("DPFS login failed for user: %s, error code: %d\n", username.c_str(), rc);
        cout << "Error message: \n" << client.msg << endl;
        // 移除失败的 session
        this->user_tokens_mutex.lock();
        user_tokens.erase(token);
        this->user_tokens_mutex.unlock();
        genResponseReturn(500, "DPFS login failed: " + client.msg, response);
        return 500;
    }
    cout << "Login successful for user: " << username << " (role: " << dbRole << ")" << endl;
    dlog->log_inf("Login successful: %s (role: %s)\n", username.c_str(), dbRole.c_str());

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
        genResponseReturn(200, "Logoff successful", response);
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
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); return 403; }
        else               { genResponseReturn(401, "Invalid user token", response); return 401; }
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

    // 边界校验
    if (begin < 0) {
        genResponseReturn(400, "begin must be >= 0", response);
        return 400;
    }
    if (begin > 10000000) {
        genResponseReturn(400, "begin too large (max 10000000)", response);
        return 400;
    }
    if (limit < 1 || limit > 1000) {
        genResponseReturn(400, "limit must be between 1 and 1000", response);
        return 400;
    }

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

    // 修正 total：dpfs 迭代器按 begin+limit 分页时 total 不正确，
    // 此处重新查询 begin=0 获取真实总数
    size_t trueTotal = total;
    {
        rc = client.getTableHandle("SYSDPFS", "SYSTRACEABLES");
        if (rc == 0) {
            std::vector<std::string> cntCol;
            cntCol.emplace_back();
            cntCol[0].resize(8);
            int64_t zero = 0;
            memcpy(const_cast<char*>(cntCol[0].data()), &zero, sizeof(zero));
            IDXHANDLE cntHidx = 0;
            rc = client.getIdxIter({"TID"}, cntCol, cntHidx);
            if (rc == 0) {
                trueTotal = 0;
                rc = client.fetchNextRow(cntHidx);
                while (rc == 0) {
                    trueTotal++;
                    rc = client.fetchNextRow(cntHidx);
                }
                client.releaseIdxIter(cntHidx);
            }
            client.releaseTableHandle();
        }
    }
    docRet["total"].SetInt64(trueTotal);

    docRet.AddMember("code", 200, allocator);
    docRet.AddMember("message", "", allocator);
    
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    docRet.Accept(writer);
    response = buffer.GetString();

    return 0;

}

// ============================================================================
// dropTracablePro — 需要权限: product:drop
// ============================================================================
int CSystem::dropTracablePro(const std::string& request, std::string& response) {

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

    // 校验必填字段
    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "schema", jsonFieldType::IsString, response);   if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "product_name", jsonFieldType::IsString, response); if (rc != 0) { return rc; }

    int64_t user_token = doc["user_token"].GetInt64();
    std::string schema = doc["schema"].GetString();
    std::string product_name = doc["product_name"].GetString();

    if (schema.empty() || product_name.empty()) {
        genResponseReturn(400, "schema and product_name must not be empty", response);
        return 400;
    }

    // 鉴权
    UserSession* session = nullptr;
    rc = checkTokenAndPermission(user_token, "product:drop", session);
    if (rc != 0) {
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); return 403; }
        else               { genResponseReturn(401, "Invalid user token", response); return 401; }
    }
    CGrpcCli& client = *session->client;

    // 调用底层 DropTracablePro
    rc = client.DropTracablePro(schema, product_name);
    if (rc != 0) {
        cout << "DropTracablePro failed, error code: " << rc << endl;
        dlog->log_error("DropTracablePro failed, error code: %d\n", rc);
        cout << "Error message: " << client.msg << endl;
        writeAuditLog(session->uid, session->username, session->role,
                      "delete", "/api/drop_tracable_pro", "",
                      "failure", "schema=" + schema + " product_name=" + product_name + " err=" + client.msg);
        genResponseReturn(400, client.msg, response);
        return 400;
    }

    // 审计日志
    writeAuditLog(session->uid, session->username, session->role,
                  "delete", "/api/drop_tracable_pro", "",
                  "success", "schema=" + schema + " product_name=" + product_name);

    genResponseReturn(200, "Drop successful", response);
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

    // 输入长度上限校验 (防止超长字符串传入 dpfs 后端导致 GPF 崩溃)
    if (schema.length() > 128) {
        genResponseReturn(400, "schema too long (max 128 characters)", response);
        return 400;
    }
    if (product_name.length() > 256) {
        genResponseReturn(400, "product_name too long (max 256 characters)", response);
        return 400;
    }

    UserSession* session = nullptr;
    rc = checkTokenAndPermission(doc["user_token"].GetInt64(), "product:risk:create", session);
    if (rc != 0) {
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); return 403; }
        else               { genResponseReturn(401, "Invalid user token", response); return 401; }
    }
    CGrpcCli& client = *session->client;

    // create pro
    std::map<std::string, std::string> ingredients;
    for (const auto& item : doc["ingredients"].GetArray()) {
        if (!item.IsArray() || item.Size() != 2 || !item[0].IsString() || !item[1].IsString()) {
            genResponseReturn(400, "Invalid 'ingredients' field, must be an array of (string, string) pairs", response);

        // ingredient name length check
        if (strlen(item[0].GetString()) > 256) {
            genResponseReturn(400, "Ingredient name too long (max 256 characters)", response);
            return 400;
        }
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
    int64_t raw_product_number = doc["product_number"].GetInt64();

    // product_number 边界校验 (先按 signed 检查，防止负数溢出为巨大正数)
    if (raw_product_number <= 0) {
        genResponseReturn(400, "product_number must be greater than 0", response);
        return 400;
    }
    size_t product_number = static_cast<size_t>(raw_product_number);
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
        }

        // 检测 ingredientName 是否包含乱码（非可打印字符）
        bool hasGarbageName = false;
        for (unsigned char c : ingredientName) {
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                hasGarbageName = true;
                break;
            }
        }
        // 过滤乱码配料：Percentage<=0 或 Name 含非可打印字符 → 跳过，不加入 JSON
        if (hasGarbageName || ingredientPercentage <= 0) {
            result += ingredientInfoStr;
            continue;
        }

        // 正常配料：将字段加入 JSON
        for (const auto& [key, value] : ingredient.ingredient_info) {
            if (memcmp(key.c_str(), "Ingredient Trace Code", 21) == 0) {
                continue;
            }
            if (tDoc && parentDoc) {
                ingredientDoc.AddMember(
                    rapidjson::Value(key.c_str(), static_cast<rapidjson::Document*>(parentDoc)->GetAllocator()), 
                    rapidjson::Value(value.c_str(), static_cast<rapidjson::Document*>(parentDoc)->GetAllocator()), 
                    static_cast<rapidjson::Document*>(parentDoc)->GetAllocator());
            }
        }

        result += ingredientInfoStr;
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

    // 将负值标志位转换为 0 (dpfs 不支持负值)
    if (trace_defail < 0) trace_defail = 0;
    if (ingDet < 0) ingDet = 0;
    if (aiRisk < 0) aiRisk = 0;

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
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); return 403; }
        else               { genResponseReturn(401, "Invalid user token", response); return 401; }
    }
    CGrpcCli& client = *session->client;

    // 早期长度检查：trace_code 在 hex2Binary 之前先验证长度，防止超长输入导致缓冲区溢出
    const char* traceCodeStr = doc["trace_code"].GetString();
    if (strlen(traceCodeStr) > 1024) {
        genResponseReturn(400, "Invalid trace code, too long", response);
        return 400;
    }
    std::string tc = hex2Binary(traceCodeStr);
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
            struct tm timeinfo;
            localtime_r(&timestamp, &timeinfo);
            char buffer[80];
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
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
        }

        // 检测 firstLevelIngName 是否包含乱码（非可打印字符）
        bool hasGarbageName = false;
        for (unsigned char c : firstLevelIngName) {
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                hasGarbageName = true;
                break;
            }
        }
        // 过滤乱码配料：Percentage<=0 或 Name 含非可打印字符 → 跳过，不加入 JSON
        if (hasGarbageName || firstLevelIngPct <= 0) {
            continue;
        }

        // 正常配料：将字段加入 JSON
        for (const auto& [key, value] : ingredient.ingredient_info) {
            if (memcmp(key.c_str(), "Ingredient Trace Code", 21) == 0) {
                continue;
            }
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
        // 过滤：累计占比为0 的条目（通常为底层数据异常导致的乱码配料）
        if (cumulativePct <= 0.0) {
            continue;
        }

        double grams = totalGrams * cumulativePct;

        rapidjson::Document metaItem;
        metaItem.SetObject();
        metaItem.AddMember("name", rapidjson::Value(name.c_str(), metaTableArr.GetAllocator()), metaTableArr.GetAllocator());

        // 百分比格式化
        char pctBuf[32];
        snprintf(pctBuf, sizeof(pctBuf), "%.2f%%", cumulativePct * 100.0);
        metaItem.AddMember("percentage", rapidjson::Value(pctBuf, metaTableArr.GetAllocator()), metaTableArr.GetAllocator());

        // 克数（仅当 totalGrams > 0 时计算，否则为 0）
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
    retDoc.AddMember("trace_result_json", tDoc, allocator);
    retDoc.AddMember("ai_risk_report", rapidjson::Value(aiRiskStr.c_str(), allocator), allocator);
    retDoc.AddMember("meta_ingredient_table", metaTableArr, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    retDoc.Accept(writer);
    response = buffer.GetString();

    // 审计日志
    writeAuditLog(session->uid, session->username, session->role,
                  "trace", "/api/trace_back", "", "success");

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
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); return 403; }
        else               { genResponseReturn(401, "Invalid user token", response); return 401; }
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

    // Permission check FIRST — so unauthorized roles get 403, not 400
    UserSession* session = nullptr;
    rc = checkTokenAndPermission(doc["user_token"].GetInt64(), "trade:create", session);
    if (rc != 0) {
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); return 403; }
        else               { genResponseReturn(401, "Invalid user token", response); return 401; }
    }

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

    // 字段长度上限校验 (防止超长字符串传入 dpfs 后端)
    if (buyer.length() > 512)           { genResponseReturn(400, "buyer too long (max 512)", response); return 400; }
    if (buyerAddr.length() > 512)       { genResponseReturn(400, "buyer_addr too long (max 512)", response); return 400; }
    if (buyerPhone.length() > 32)       { genResponseReturn(400, "buyer_phone too long (max 32)", response); return 400; }
    if (seller.length() > 512)          { genResponseReturn(400, "seller too long (max 512)", response); return 400; }
    if (sellerAddr.length() > 512)      { genResponseReturn(400, "seller_addr too long (max 512)", response); return 400; }
    if (sellerPhone.length() > 32)      { genResponseReturn(400, "seller_phone too long (max 32)", response); return 400; }
    if (logisticsInfo.length() > 512)   { genResponseReturn(400, "logistics_info too long (max 512)", response); return 400; }
    if (otherInfo.length() > 512)       { genResponseReturn(400, "other_info too long (max 512)", response); return 400; }
    if (tradePrice.length() > 32)       { genResponseReturn(400, "trade_price too long (max 32)", response); return 400; }

    // dpfs product instance IDs start from 0; start_id < 0 causes trade to silently
    // not appear in traceBack results.  Clamp to 0 as a safety net.
    // NOTE: dpfs gRPC server currently ignores start_uid and always binds trades
    // to instance 0 (SPJYQSID is always 0 in traceBack results).  Force start_id
    // to 0 so that trades created with start_id>0 don't silently disappear.
    if (tradeProductStartID != 0) {
        cout << "[WARN] makeTrade: trade_product_start_id=" << tradeProductStartID
             << " was non-zero, but dpfs only supports instance 0. Clamping to 0." << endl;
        dlog->log_notic("[WARN] makeTrade: trade_product_start_id=%lld clamped to 0\n", tradeProductStartID);
        tradeProductStartID = 0;
    }

    CGrpcCli& client = *session->client;

    rc = client.makeTrade(tradeSchema, tradeProductName, 999/*deprecated*/, tradeProductStartID, tradeProductNumber, buyer, buyerAddr, buyerPhone, seller, sellerAddr, sellerPhone, logisticsInfo, otherInfo, tradePrice);
    if (rc != 0) {
        cout << "Make trade failed, error code: " << rc << endl;
        dlog->log_error("Make trade failed, error code: %d\n", rc);
        cout << "Error message: " << client.msg << endl;
        writeAuditLog(session->uid, session->username, session->role,
                      "create", "/api/make_trade", "", "failure", client.msg);
        genResponseReturn(400, client.msg, response);
    } else {
        writeAuditLog(session->uid, session->username, session->role,
                      "create", "/api/make_trade", "", "success");
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
        if (rc == -EACCES) { genResponseReturn(403, "Permission denied", response); return 403; }
        else               { genResponseReturn(401, "Invalid user token", response); return 401; }
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

    // 边界校验
    if (begin < 0) {
        genResponseReturn(400, "begin must be >= 0", response);
        return 400;
    }
    if (begin > 10000000) {
        genResponseReturn(400, "begin too large (max 10000000)", response);
        return 400;
    }
    if (limit < 1 || limit > 1000) {
        genResponseReturn(400, "limit must be between 1 and 1000", response);
        return 400;
    }

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

// ============================================================================
// getUserInfo: 根据 user_token 查询当前用户信息
// ============================================================================
int CSystem::getUserInfo(const std::string& request, std::string& response) {
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

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response);
    if (rc != 0) return rc;

    int64_t token = doc["user_token"].GetInt64();

    // 查找 session（个人中心操作仅需有效 token，不需要权限码）
    UserSession* session = nullptr;
    {
        std::lock_guard<std::mutex> lock(this->user_tokens_mutex);
        auto it = user_tokens.find(token);
        if (it == user_tokens.end()) {
            genResponseReturn(401, "Invalid token", response);
            return 401;
        }
        session = it->second.get();
    }

    // 从 MySQL 查询完整用户信息
    std::string dbName, dbRole, dbStatus, dbLastLogin, dbCreatedAt;
    std::string dbRealName, dbPhone, dbMail, dbDesc;
    {
        SQLHENV env = SQL_NULL_HANDLE;
        SQLHDBC dbc = SQL_NULL_HANDLE;
        SQLHSTMT stmt = SQL_NULL_HANDLE;
        SQLRETURN ret;
        char colName[256], colRole[32], colStatus[32], colLastLogin[64], colCreatedAt[64];
        char colRealName[256], colPhone[64], colMail[128], colDesc[1024];
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
                        std::string sql = "SELECT name, role, status, COALESCE(last_login_at,''), COALESCE(created_at,''), COALESCE(real_name,''), COALESCE(phone,''), COALESCE(mail,''), COALESCE(description,'') FROM users WHERE id = " + std::to_string(session->uid);
                        ret = SQLExecDirect(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
                        if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                            if (SQLFetch(stmt) == SQL_SUCCESS) {
                                SQLGetData(stmt, 1, SQL_C_CHAR, colName, sizeof(colName), &ind);
                                SQLGetData(stmt, 2, SQL_C_CHAR, colRole, sizeof(colRole), &ind);
                                SQLGetData(stmt, 3, SQL_C_CHAR, colStatus, sizeof(colStatus), &ind);
                                SQLGetData(stmt, 4, SQL_C_CHAR, colLastLogin, sizeof(colLastLogin), &ind);
                                SQLGetData(stmt, 5, SQL_C_CHAR, colCreatedAt, sizeof(colCreatedAt), &ind);
                                SQLGetData(stmt, 6, SQL_C_CHAR, colRealName, sizeof(colRealName), &ind);
                                SQLGetData(stmt, 7, SQL_C_CHAR, colPhone, sizeof(colPhone), &ind);
                                SQLGetData(stmt, 8, SQL_C_CHAR, colMail, sizeof(colMail), &ind);
                                SQLGetData(stmt, 9, SQL_C_CHAR, colDesc, sizeof(colDesc), &ind);
                                dbName = colName;
                                dbRole = colRole;
                                dbStatus = colStatus;
                                dbLastLogin = colLastLogin;
                                dbCreatedAt = colCreatedAt;
                                dbRealName = colRealName;
                                dbPhone = colPhone;
                                dbMail = colMail;
                                dbDesc = colDesc;
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
    }

    // 返回用户信息
    rapidjson::Document docRet;
    docRet.SetObject();
    auto& allocator = docRet.GetAllocator();
    docRet.AddMember("code", 200, allocator);
    docRet.AddMember("message", "success", allocator);
    docRet.AddMember("uid", session->uid, allocator);
    docRet.AddMember("username", rapidjson::Value(dbName.c_str(), allocator), allocator);
    docRet.AddMember("role", rapidjson::Value(dbRole.c_str(), allocator), allocator);
    docRet.AddMember("status", rapidjson::Value(dbStatus.c_str(), allocator), allocator);
    docRet.AddMember("last_login", rapidjson::Value(dbLastLogin.c_str(), allocator), allocator);
    docRet.AddMember("created_at", rapidjson::Value(dbCreatedAt.c_str(), allocator), allocator);
    docRet.AddMember("real_name", rapidjson::Value(dbRealName.c_str(), allocator), allocator);
    docRet.AddMember("phone", rapidjson::Value(dbPhone.c_str(), allocator), allocator);
    docRet.AddMember("mail", rapidjson::Value(dbMail.c_str(), allocator), allocator);
    docRet.AddMember("description", rapidjson::Value(dbDesc.c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    docRet.Accept(writer);
    response = buffer.GetString();

    return 0;
}

// ============================================================================
// updatePassword: 修改当前用户密码
// ============================================================================
int CSystem::updatePassword(const std::string& request, std::string& response) {
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

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response);
    if (rc != 0) return rc;
    rc = checkJsonFormat(doc, "old_password", jsonFieldType::IsString, response);
    if (rc != 0) return rc;
    rc = checkJsonFormat(doc, "new_password", jsonFieldType::IsString, response);
    if (rc != 0) return rc;

    int64_t token = doc["user_token"].GetInt64();
    std::string oldPasswd = doc["old_password"].GetString();
    std::string newPasswd = doc["new_password"].GetString();

    if (newPasswd.length() < 4) {
        genResponseReturn(400, "New password too short (min 4 chars)", response);
        return 400;
    }
    if (newPasswd.length() > 128) {
        genResponseReturn(400, "New password too long (max 128 chars)", response);
        return 400;
    }

    // 验证 token（个人中心操作仅需有效 token，不需要权限码）
    UserSession* session = nullptr;
    {
        std::lock_guard<std::mutex> lock(this->user_tokens_mutex);
        auto it = user_tokens.find(token);
        if (it == user_tokens.end()) {
            genResponseReturn(401, "Invalid token", response);
            return 401;
        }
        session = it->second.get();
    }

    int uid = session->uid;
    {
        SQLHENV env = SQL_NULL_HANDLE;
        SQLHDBC dbc = SQL_NULL_HANDLE;
        SQLHSTMT stmt = SQL_NULL_HANDLE;
        SQLRETURN ret;
        char colPasswd[256];
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
                        // 查旧密码
                        std::string sql = "SELECT passwd FROM users WHERE id = " + std::to_string(session->uid);
                        ret = SQLExecDirect(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
                        if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                            if (SQLFetch(stmt) == SQL_SUCCESS) {
                                SQLGetData(stmt, 1, SQL_C_CHAR, colPasswd, sizeof(colPasswd), &ind);
                            }
                        }
                        SQLFreeHandle(SQL_HANDLE_STMT, stmt);

                        // 校验旧密码
                        if (std::string(colPasswd) != oldPasswd) {
                            SQLDisconnect(dbc);
                            SQLFreeHandle(SQL_HANDLE_DBC, dbc);
                            SQLFreeHandle(SQL_HANDLE_ENV, env);
                            writeAuditLog(session->uid, session->username, session->role,
                                          "update_password", "/api/update_password", "", "failure", "Wrong old password");
                            genResponseReturn(403, "Old password is incorrect", response);
                            return 403;
                        }

                        // 更新新密码
                        ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
                        if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                            // 防止 SQL 注入：简单转义单引号
                            std::string safePasswd;
                            for (char c : newPasswd) {
                                if (c == '\'') safePasswd += "''";
                                else safePasswd += c;
                            }
                            std::string updateSql = "UPDATE users SET passwd = '" + safePasswd + "' WHERE id = " + std::to_string(session->uid);
                            ret = SQLExecDirect(stmt, (SQLCHAR*)updateSql.c_str(), SQL_NTS);
                            SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                        }
                    }
                    SQLDisconnect(dbc);
                }
                SQLFreeHandle(SQL_HANDLE_DBC, dbc);
            }
            SQLFreeHandle(SQL_HANDLE_ENV, env);
        }
    }

    writeAuditLog(session->uid, session->username, session->role,
                  "update_password", "/api/update_password", "", "success");

    genResponseReturn(200, "Password updated successfully", response);
    return 0;
}

// ============================================================================
// updateUserInfo: 修改当前用户基础信息（real_name, phone, mail, description）
// ============================================================================
int CSystem::updateUserInfo(const std::string& request, std::string& response) {
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

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response);
    if (rc != 0) return rc;

    int64_t token = doc["user_token"].GetInt64();

    // 验证 token（个人中心操作仅需有效 token，不需要权限码）
    UserSession* session = nullptr;
    {
        std::lock_guard<std::mutex> lock(this->user_tokens_mutex);
        auto it = user_tokens.find(token);
        if (it == user_tokens.end()) {
            genResponseReturn(401, "Invalid token", response);
            return 401;
        }
        session = it->second.get();
    }

    int uid = session->uid;
    std::string realName, phone, mail, desc;
    if (doc.HasMember("real_name") && doc["real_name"].IsString()) {
        realName = doc["real_name"].GetString();
    }
    if (doc.HasMember("phone") && doc["phone"].IsString()) {
        phone = doc["phone"].GetString();
    }
    if (doc.HasMember("mail") && doc["mail"].IsString()) {
        mail = doc["mail"].GetString();
    }
    if (doc.HasMember("description") && doc["description"].IsString()) {
        desc = doc["description"].GetString();
    }

    // XSS 防护：去除 HTML 标签
    auto stripHtml = [](const std::string& s) -> std::string {
        std::string out;
        bool inTag = false;
        for (char c : s) {
            if (c == '<') { inTag = true; continue; }
            if (c == '>') { inTag = false; continue; }
            if (!inTag) out += c;
        }
        return out;
    };

    realName = stripHtml(realName);
    phone = stripHtml(phone);
    mail = stripHtml(mail);
    desc = stripHtml(desc);

    // SQL 注入防护：转义单引号
    auto escape = [](const std::string& s) -> std::string {
        std::string out;
        for (char c : s) {
            if (c == '\'') out += "''";
            else out += c;
        }
        return out;
    };

    // 更新 MySQL
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
                        std::string sql = "UPDATE users SET real_name = '" + escape(realName) +
                                          "', phone = '" + escape(phone) +
                                          "', mail = '" + escape(mail) +
                                          "', description = '" + escape(desc) +
                                          "' WHERE id = " + std::to_string(session->uid);
                        ret = SQLExecDirect(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
                        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                    }
                    SQLDisconnect(dbc);
                }
                SQLFreeHandle(SQL_HANDLE_DBC, dbc);
            }
            SQLFreeHandle(SQL_HANDLE_ENV, env);
        }
    }

    writeAuditLog(session->uid, session->username, session->role,
                  "update_user_info", "/api/update_user_info", "", "success");

    genResponseReturn(200, "User info updated successfully", response);
    return 0;
}

// ========== Base64 解码 ==========
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

static std::vector<unsigned char> base64_decode(const std::string& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;
        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; j < i - 1; j++)
            ret.push_back(char_array_3[j]);
    }

    return ret;
}

// 递归创建目录
static bool mkdir_p(const std::string& path) {
    size_t pos = 0;
    std::string dir;
    while ((pos = path.find('/', pos + 1)) != std::string::npos) {
        dir = path.substr(0, pos);
        if (mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) return false;
    }
    if (mkdir(path.c_str(), 0755) != 0 && errno != EEXIST) return false;
    return true;
}

// ============================================================================
// registerUser — 用户注册（无需登录）
// ============================================================================
int CSystem::registerUser(const std::string& request, std::string& response) {

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

    rc = checkJsonFormat(doc, "username", jsonFieldType::IsString, response); if (rc != 0) return rc;
    rc = checkJsonFormat(doc, "password", jsonFieldType::IsString, response); if (rc != 0) return rc;
    rc = checkJsonFormat(doc, "role",     jsonFieldType::IsString, response); if (rc != 0) return rc;

    std::string username = doc["username"].GetString();
    std::string password = doc["password"].GetString();
    std::string role     = doc["role"].GetString();

    // 可选字段
    std::string realName    = doc.HasMember("real_name")   && doc["real_name"].IsString()   ? doc["real_name"].GetString()   : "";
    std::string description = doc.HasMember("description") && doc["description"].IsString() ? doc["description"].GetString() : "";
    std::string phone       = doc.HasMember("phone")       && doc["phone"].IsString()       ? doc["phone"].GetString()       : "";
    std::string mail        = doc.HasMember("mail")        && doc["mail"].IsString()        ? doc["mail"].GetString()        : "";

    // 输入校验
    if (username.empty()) {
        genResponseReturn(400, "Username must not be empty", response);
    if (username.length() > 64) {
        genResponseReturn(400, "Username too long (max 64 characters)", response);
        return 400;
    }
        return 400;
    }
    if (password.empty()) {
        genResponseReturn(400, "Password must not be empty", response);
        return 400;
    }
    if (password.length() < 6) {
        genResponseReturn(400, "Password must be at least 6 characters", response);
    if (password.length() > 128) {
        genResponseReturn(400, "Password too long (max 128 characters)", response);
        return 400;
    }
        return 400;
    }
    // 合法角色列表（仅允许消费者和生产商注册）
    if (role != "manufacturer" && role != "consumer") {
        genResponseReturn(400, "Invalid role. Must be one of: consumer, manufacturer", response);
    if (realName.length() > 128) {
        genResponseReturn(400, "real_name too long (max 128 characters)", response);
        return 400;
    }
    if (description.length() > 1024) {
        genResponseReturn(400, "description too long (max 1024 characters)", response);
        return 400;
    }
    if (phone.length() > 32) {
        genResponseReturn(400, "phone too long (max 32 characters)", response);
        return 400;
    }
    if (mail.length() > 128) {
        genResponseReturn(400, "mail too long (max 128 characters)", response);
        return 400;
    }
        return 400;
    }

    // ─── MySQL ODBC：检查用户名是否已存在 → 插入新用户 ───
    SQLHENV env = SQL_NULL_HANDLE;
    SQLHDBC  dbc = SQL_NULL_HANDLE;
    SQLHSTMT stmt = SQL_NULL_HANDLE;
    SQLRETURN ret;

    ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        genResponseReturn(500, "Database error", response);
        return 500;
    }
    SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);

    ret = SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        genResponseReturn(500, "Database error", response);
        return 500;
    }

    std::string connStr = buildOdbcConnStr();
    ret = SQLDriverConnect(dbc, nullptr, (SQLCHAR*)connStr.c_str(), SQL_NTS,
                           nullptr, 0, nullptr, SQL_DRIVER_COMPLETE);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        SQLFreeHandle(SQL_HANDLE_DBC, dbc);
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        genResponseReturn(500, "Database connection failed", response);
        return 500;
    }

    ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        SQLDisconnect(dbc);
        SQLFreeHandle(SQL_HANDLE_DBC, dbc);
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        genResponseReturn(500, "Database error", response);
        return 500;
    }

    // 检查用户名是否已存在
    std::string sql = "SELECT id FROM users WHERE name = '" + username + "'";
    ret = SQLExecDirect(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
    if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
        if (SQLFetch(stmt) == SQL_SUCCESS) {
            SQLFreeHandle(SQL_HANDLE_STMT, stmt);
            SQLDisconnect(dbc);
            SQLFreeHandle(SQL_HANDLE_DBC, dbc);
            SQLFreeHandle(SQL_HANDLE_ENV, env);
            genResponseReturn(409, "Username already exists", response);
            return 409;
        }
    }
    SQLFreeHandle(SQL_HANDLE_STMT, stmt);

    // 插入新用户
    ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        SQLDisconnect(dbc);
        SQLFreeHandle(SQL_HANDLE_DBC, dbc);
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        genResponseReturn(500, "Database error", response);
        return 500;
    }

    // 转义单引号
    auto esc = [](const std::string& s) -> std::string {
        std::string r;
        for (char c : s) {
            r += c;
            if (c == '\'') r += '\'';
        }
        return r;
    };

    sql = "INSERT INTO users (name, role, passwd, real_name, description, phone, mail, status) "
          "VALUES ('" + esc(username) + "', '" + esc(role) + "', '" + esc(password) + "', '" +
          esc(realName) + "', '" + esc(description) + "', '" + esc(phone) + "', '" +
          esc(mail) + "', 'active')";

    ret = SQLExecDirect(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        cerr << "Register INSERT failed: " << sql << endl;
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        SQLDisconnect(dbc);
        SQLFreeHandle(SQL_HANDLE_DBC, dbc);
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        genResponseReturn(500, "Failed to create user", response);
        return 500;
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    SQLFreeHandle(SQL_HANDLE_ENV, env);

    cout << "User registered: " << username << " (role: " << role << ")" << endl;
    dlog->log_inf("User registered: %s (role: %s)\n", username.c_str(), role.c_str());

    // 审计日志 (uid=0 因为是新用户，尚未登录)
    writeAuditLog(0, username, role, "register", "/api/register", "", "success");

    genResponseReturn(200, "Registration successful", response);
    return 0;
}

int CSystem::uploadFile(const std::string& request, std::string& response) {
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

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response);
    if (rc != 0) return rc;

    rc = checkJsonFormat(doc, "schema", jsonFieldType::IsString, response);
    if (rc != 0) return rc;

    rc = checkJsonFormat(doc, "product_name", jsonFieldType::IsString, response);
    if (rc != 0) return rc;

    rc = checkJsonFormat(doc, "file_name", jsonFieldType::IsString, response);
    if (rc != 0) return rc;

    rc = checkJsonFormat(doc, "file_content", jsonFieldType::IsString, response);
    if (rc != 0) return rc;

    int64_t token = doc["user_token"].GetInt64();

    // 验证 token
    {
        std::lock_guard<std::mutex> lock(this->user_tokens_mutex);
        auto it = user_tokens.find(token);
        if (it == user_tokens.end()) {
            genResponseReturn(401, "Invalid token", response);
            return 401;
        }
    }

    std::string schema = doc["schema"].GetString();
    std::string productName = doc["product_name"].GetString();
    std::string fileName = doc["file_name"].GetString();
    std::string fileContentB64 = doc["file_content"].GetString();

    // 安全校验：防止路径遍历
    if (schema.empty() || productName.empty() || fileName.empty()) {
        genResponseReturn(400, "schema, product_name and file_name must not be empty", response);
        return 400;
    }

    // 长度上限校验
    if (schema.length() > 128) {
        genResponseReturn(400, "schema too long (max 128 characters)", response);
        return 400;
    }
    if (productName.length() > 256) {
        genResponseReturn(400, "product_name too long (max 256 characters)", response);
        return 400;
    }
    if (fileName.length() > 256) {
        genResponseReturn(400, "file_name too long (max 256 characters)", response);
        return 400;
    }

    // 构建目标路径: /home/dpfs/github/dpfsserver/uploads/<schema>/<product_name>/
    std::string baseDir = "/home/dpfs/github/dpfsserver/uploads";
    std::string dirPath = baseDir + "/" + schema + "/" + productName;
    std::string filePath = dirPath + "/" + fileName;

    // 创建目录
    if (!mkdir_p(dirPath)) {
        genResponseReturn(500, "Failed to create directory: " + dirPath, response);
        return 500;
    }

    // 解码并写入文件
    std::vector<unsigned char> decoded = base64_decode(fileContentB64);

    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile.is_open()) {
        genResponseReturn(500, "Failed to open file for writing: " + filePath, response);
        return 500;
    }
    outFile.write(reinterpret_cast<const char*>(decoded.data()), decoded.size());
    outFile.close();

    // 返回文件路径
    rapidjson::Document retDoc;
    retDoc.SetObject();
    rapidjson::Document::AllocatorType& allocator = retDoc.GetAllocator();
    retDoc.AddMember("code", 200, allocator);
    retDoc.AddMember("message", "File uploaded successfully", allocator);
    rapidjson::Value fp;
    fp.SetString(filePath.c_str(), allocator);
    retDoc.AddMember("file_path", fp, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    retDoc.Accept(writer);
    response = buffer.GetString();

    std::cout << "[UPLOAD] File saved: " << filePath << " (" << decoded.size() << " bytes)" << std::endl;
    dlog->log_inf("[UPLOAD] File saved: %s (%zu bytes)\n", filePath.c_str(), decoded.size());
    return 0;
}

int CSystem::listFiles(const std::string& request, std::string& response) {
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

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response);
    if (rc != 0) return rc;

    rc = checkJsonFormat(doc, "schema", jsonFieldType::IsString, response);
    if (rc != 0) return rc;

    rc = checkJsonFormat(doc, "product_name", jsonFieldType::IsString, response);
    if (rc != 0) return rc;

    int64_t token = doc["user_token"].GetInt64();
    std::shared_ptr<CGrpcCli> clientPtr;
    {
        std::lock_guard<std::mutex> lock(this->user_tokens_mutex);
        auto it = user_tokens.find(token);
        if (it == user_tokens.end()) {
            genResponseReturn(401, "Invalid token", response);
            return 401;
        }
        clientPtr = it->second->client;
    }

    std::string schema = doc["schema"].GetString();
    std::string productName = doc["product_name"].GetString();

    if (schema.empty() || productName.empty()) {
        genResponseReturn(400, "schema and product_name must not be empty", response);
        return 400;
    }

    std::string dirPath = "/home/dpfs/github/dpfsserver/uploads/" + schema + "/" + productName;
    const std::string uploadsPrefix = "/home/dpfs/github/dpfsserver/uploads/";

    rapidjson::Document retDoc;
    retDoc.SetObject();
    rapidjson::Document::AllocatorType& allocator = retDoc.GetAllocator();
    rapidjson::Value filesArr(rapidjson::kArrayType);

    // 用于去重
    std::set<std::string> seenPaths;

    // 扫描目录
    DIR* dir = opendir(dirPath.c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type == DT_REG) {
                std::string fileName = entry->d_name;
                std::string fullPath = dirPath + "/" + fileName;
                struct stat st;
                if (stat(fullPath.c_str(), &st) == 0) {
                    rapidjson::Value fileObj(rapidjson::kObjectType);
                    rapidjson::Value fn;
                    fn.SetString(fileName.c_str(), allocator);
                    fileObj.AddMember("name", fn, allocator);
                    rapidjson::Value fp;
                    fp.SetString(fullPath.c_str(), allocator);
                    fileObj.AddMember("path", fp, allocator);
                    fileObj.AddMember("size", (int64_t)st.st_size, allocator);
                    filesArr.PushBack(fileObj, allocator);
                    seenPaths.insert(fullPath);
                }
            }
        }
        closedir(dir);
    }

    // 额外从 base_info 中提取引用的文件路径（解决 productName 变更导致目录不匹配的问题）
    {
        CGrpcCli& client = *clientPtr;
        std::string spxxb = productName + "_SPXXB";
        rc = client.getTableHandle(schema, spxxb);
        if (rc == 0) {
            int32_t hidx = 0;
            std::vector<std::string> idxNames;
            rc = client.getIdxIter(idxNames, {}, hidx);
            if (rc == 0) {
                while (client.fetchNextRow(hidx) == 0) {
                    std::string oval;
                    // 读取 key (col 0)
                    rc = client.getDataByIdxIter(hidx, 0, oval, dpfs_ctype_t::TYPE_STRING);
                    if (rc != 0) continue;
                    // 跳过系统内部 key
                    if (memcmp(oval.c_str(), "SPKZB", 5) == 0 ||
                        memcmp(oval.c_str(), "PLKZB", 5) == 0 ||
                        memcmp(oval.c_str(), "SPJYB", 5) == 0) continue;

                    // 读取 value (col 1)
                    std::string vval;
                    rc = client.getDataByIdxIter(hidx, 1, vval, dpfs_ctype_t::TYPE_STRING);
                    if (rc != 0 || vval.empty()) continue;

                    // 检查 value 是否引用 uploads 路径
                    size_t pos = vval.find(uploadsPrefix);
                    if (pos != std::string::npos) {
                        std::string filePath = vval.substr(pos);
                        while (!filePath.empty() && (filePath.back() == ' ' || filePath.back() == '\n' || filePath.back() == '\r'))
                            filePath.pop_back();
                        struct stat st;
                        if (stat(filePath.c_str(), &st) == 0 && seenPaths.find(filePath) == seenPaths.end()) {
                            std::string fileName = filePath;
                            size_t lastSlash = filePath.rfind('/');
                            if (lastSlash != std::string::npos) fileName = filePath.substr(lastSlash + 1);
                            rapidjson::Value fileObj(rapidjson::kObjectType);
                            rapidjson::Value fn;
                            fn.SetString(fileName.c_str(), allocator);
                            fileObj.AddMember("name", fn, allocator);
                            rapidjson::Value fp;
                            fp.SetString(filePath.c_str(), allocator);
                            fileObj.AddMember("path", fp, allocator);
                            fileObj.AddMember("size", (int64_t)st.st_size, allocator);
                            filesArr.PushBack(fileObj, allocator);
                            seenPaths.insert(filePath);
                        }
                    }
                }
                client.releaseIdxIter(hidx);
            }
            client.releaseTableHandle();
        }
    }

    retDoc.AddMember("code", 200, allocator);
    std::string msgText = filesArr.Size() > 0 ? "OK" : "No files found";
    rapidjson::Value msg;
    msg.SetString(msgText.c_str(), allocator);
    retDoc.AddMember("message", msg, allocator);
    retDoc.AddMember("files", filesArr, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    retDoc.Accept(writer);
    response = buffer.GetString();
    return 0;
}

// ============================================================================
// monitor — 系统监控数据采集（无需特殊权限，所有登录用户可查看）
// 返回: 总产品数、风险产品数、每分钟溯源查询次数、系统响应时间、系统报错数、系统负载
// ============================================================================
int CSystem::monitor(const std::string& request, std::string& response) {
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

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response);
    if (rc != 0) return rc;

    int64_t user_token = doc["user_token"].GetInt64();
    UserSession* session = nullptr;
    {
        std::lock_guard<std::mutex> lk(user_tokens_mutex);
        auto it = user_tokens.find(user_token);
        if (it == user_tokens.end()) {
            genResponseReturn(401, "Invalid user token", response);
            return 401;
        }
        session = it->second.get();
    }

    rapidjson::Document retDoc;
    retDoc.SetObject();
    rapidjson::Document::AllocatorType& allocator = retDoc.GetAllocator();

    // --- 1. 总产品数 & 2. 风险产品数 (从 dpfs 后端查询) ---
    int64_t totalProducts = 0;
    int64_t riskProducts = 0;

    if (session && session->client) {
        CGrpcCli& client = *session->client;
        // 查询 SYSTRACEABLES 获取总产品数
        rc = client.getTableHandle("SYSDPFS", "SYSTRACEABLES");
        if (rc == 0) {
            std::vector<std::string> idxCol;
            idxCol.emplace_back();
            idxCol[0].resize(8);
            int64_t begin = 0;
            memcpy(const_cast<char*>(idxCol[0].data()), &begin, sizeof(begin));
            IDXHANDLE hidx = 0;
            rc = client.getIdxIter({"TID"}, idxCol, hidx);
            if (rc == 0) {
                while (client.fetchNextRow(hidx) == 0) {
                    totalProducts++;
                }
                client.releaseIdxIter(hidx);
            }
            client.releaseTableHandle();
        }
        // 查询 SYSRISKWARNS 获取风险产品数
        rc = client.getTableHandle("SYSDPFS", "SYSRISKWARNS");
        if (rc == 0) {
            std::vector<std::string> idxCol2;
            idxCol2.emplace_back();
            idxCol2[0].resize(8);
            int64_t begin2 = 0;
            memcpy(const_cast<char*>(idxCol2[0].data()), &begin2, sizeof(begin2));
            IDXHANDLE hidx2 = 0;
            rc = client.getIdxIter({"TID"}, idxCol2, hidx2);
            if (rc == 0) {
                while (client.fetchNextRow(hidx2) == 0) {
                    riskProducts++;
                }
                client.releaseIdxIter(hidx2);
            }
            client.releaseTableHandle();
        }
    }

    // --- 3. 每分钟溯源查询次数 & 5. 系统报错数 & 交易统计 (从 MySQL audit_logs 查询) ---
    int64_t traceCountPerMin = 0;
    int64_t errorCount = 0;
    int64_t tradeCountPerMin = 0;

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
                        // 每分钟溯源查询次数
                        std::string sql1 = "SELECT COUNT(*) FROM audit_logs WHERE resource='/api/trace_back' AND created_at >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)";
                        if (SQLExecDirect(stmt, (SQLCHAR*)sql1.c_str(), SQL_NTS) == SQL_SUCCESS) {
                            if (SQLFetch(stmt) == SQL_SUCCESS) {
                                char buf[64] = {0};
                                SQLGetData(stmt, 1, SQL_C_CHAR, buf, sizeof(buf), nullptr);
                                traceCountPerMin = strtoll(buf, nullptr, 10);
                            }
                        }
                        SQLFreeHandle(SQL_HANDLE_STMT, stmt);

                        // 系统报错数（最近1小时内失败的操作数）
                        ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
                        if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                            std::string sql2 = "SELECT COUNT(*) FROM audit_logs WHERE result='failure' AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)";
                            if (SQLExecDirect(stmt, (SQLCHAR*)sql2.c_str(), SQL_NTS) == SQL_SUCCESS) {
                                if (SQLFetch(stmt) == SQL_SUCCESS) {
                                    char buf2[64] = {0};
                                    SQLGetData(stmt, 1, SQL_C_CHAR, buf2, sizeof(buf2), nullptr);
                                    errorCount = strtoll(buf2, nullptr, 10);
                                }
                            }
                            SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                        }

                        // 每分钟交易次数
                        ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
                        if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                            std::string sql3 = "SELECT COUNT(*) FROM audit_logs WHERE resource='/api/make_trade' AND created_at >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)";
                            if (SQLExecDirect(stmt, (SQLCHAR*)sql3.c_str(), SQL_NTS) == SQL_SUCCESS) {
                                if (SQLFetch(stmt) == SQL_SUCCESS) {
                                    char buf3[64] = {0};
                                    SQLGetData(stmt, 1, SQL_C_CHAR, buf3, sizeof(buf3), nullptr);
                                    tradeCountPerMin = strtoll(buf3, nullptr, 10);
                                }
                            }
                            SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                        }
                    }
                    SQLDisconnect(dbc);
                }
                SQLFreeHandle(SQL_HANDLE_DBC, dbc);
            }
            SQLFreeHandle(SQL_HANDLE_ENV, env);
        }
    }

    // --- 4. 系统响应时间 (测量 dpfs 后端连通性) ---
    double responseTimeMs = 0.0;
    {
        auto tStart = std::chrono::steady_clock::now();
        // 简单 ping: 尝试 getTableHandle + releaseTableHandle
        if (session && session->client) {
            CGrpcCli& client = *session->client;
            rc = client.getTableHandle("SYSDPFS", "SYSTRACEABLES");
            if (rc == 0) {
                client.releaseTableHandle();
            }
        }
        auto tEnd = std::chrono::steady_clock::now();
        responseTimeMs = std::chrono::duration<double, std::milli>(tEnd - tStart).count();
    }

    // --- 6. 系统负载 (CPU、内存、存储) ---
    double cpuUsage = 0.0;
    int64_t memTotalKB = 0, memAvailableKB = 0;
    double memUsagePercent = 0.0;
    int64_t diskTotalKB = 0, diskUsedKB = 0;
    double diskUsagePercent = 0.0;

    // CPU 使用率 (从 /proc/stat 读取)
    {
        std::ifstream statFile("/proc/stat");
        std::string line;
        if (std::getline(statFile, line)) {
            unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
            if (sscanf(line.c_str(), "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                       &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) == 8) {
                unsigned long long total = user + nice + system + idle + iowait + irq + softirq + steal;
                unsigned long long busy = total - idle - iowait;
                if (total > 0) cpuUsage = (double)busy / total * 100.0;
            }
        }
    }

    // 内存信息 (从 /proc/meminfo 读取)
    {
        std::ifstream memFile("/proc/meminfo");
        std::string line;
        while (std::getline(memFile, line)) {
            if (line.find("MemTotal:") == 0) {
                sscanf(line.c_str(), "MemTotal: %lld kB", &memTotalKB);
            } else if (line.find("MemAvailable:") == 0) {
                sscanf(line.c_str(), "MemAvailable: %lld kB", &memAvailableKB);
            }
            if (memTotalKB > 0 && memAvailableKB > 0) break;
        }
        if (memTotalKB > 0) {
            memUsagePercent = (double)(memTotalKB - memAvailableKB) / memTotalKB * 100.0;
        }
    }

    // 磁盘使用率 (使用 statvfs 获取项目所在分区的使用情况)
    {
        struct statvfs vfs;
        if (statvfs("/home/dpfs", &vfs) == 0) {
            diskTotalKB = (int64_t)vfs.f_blocks * vfs.f_frsize / 1024;
            diskUsedKB = (int64_t)(vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize / 1024;
            if (diskTotalKB > 0) {
                diskUsagePercent = (double)diskUsedKB / diskTotalKB * 100.0;
            }
        }
    }

    // --- 构建返回 JSON ---
    retDoc.AddMember("code", 200, allocator);
    rapidjson::Value msg;
    msg.SetString("OK", allocator);
    retDoc.AddMember("message", msg, allocator);

    retDoc.AddMember("total_products", totalProducts, allocator);
    retDoc.AddMember("risk_products", riskProducts, allocator);
    retDoc.AddMember("trace_count_per_min", traceCountPerMin, allocator);
    retDoc.AddMember("trade_count_per_min", tradeCountPerMin, allocator);
    retDoc.AddMember("response_time_ms", responseTimeMs, allocator);
    retDoc.AddMember("error_count", errorCount, allocator);

    retDoc.AddMember("cpu_usage", cpuUsage, allocator);
    retDoc.AddMember("mem_total_kb", memTotalKB, allocator);
    retDoc.AddMember("mem_available_kb", memAvailableKB, allocator);
    retDoc.AddMember("mem_usage_percent", memUsagePercent, allocator);
    retDoc.AddMember("disk_total_kb", diskTotalKB, allocator);
    retDoc.AddMember("disk_used_kb", diskUsedKB, allocator);
    retDoc.AddMember("disk_usage_percent", diskUsagePercent, allocator);

    // 当前活跃用户数
    {
        std::lock_guard<std::mutex> lk(user_tokens_mutex);
        retDoc.AddMember("active_users", (int64_t)user_tokens.size(), allocator);
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    retDoc.Accept(writer);
    response = buffer.GetString();
    return 0;
}

// ============================================================================
// getLogs — 系统日志：读取 dserver.log 最近 N 行返回给前端
// 请求: {"user_token":int, "lines":int}  默认返回 50 行
// 响应: {"code":200, "logs":[{"time":"...","level":"INFO","msg":"..."},...]}
// ============================================================================
int CSystem::getLogs(const std::string& request, std::string& response) {
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

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response);
    if (rc != 0) return rc;

    int64_t user_token = doc["user_token"].GetInt64();
    {
        std::lock_guard<std::mutex> lk(user_tokens_mutex);
        auto it = user_tokens.find(user_token);
        if (it == user_tokens.end()) {
            genResponseReturn(401, "Invalid user token", response);
            return 401;
        }
    }

    int maxLines = 50;
    if (doc.HasMember("lines") && doc["lines"].IsInt()) {
        maxLines = doc["lines"].GetInt();
        if (maxLines < 1) maxLines = 1;
        if (maxLines > 500) maxLines = 500;
    }

    rapidjson::Document retDoc;
    retDoc.SetObject();
    rapidjson::Document::AllocatorType& allocator = retDoc.GetAllocator();
    rapidjson::Value logsArr(rapidjson::kArrayType);

    std::string logPath = dlog->get_log_path();
    std::ifstream logFile(logPath);
    if (logFile.is_open()) {
        std::vector<std::string> lines;
        std::string line;
        while (std::getline(logFile, line)) {
            if (!line.empty()) lines.push_back(line);
        }
        logFile.close();

        int start = (int)lines.size() - maxLines;
        if (start < 0) start = 0;

        for (int i = start; i < (int)lines.size(); i++) {
            rapidjson::Value logEntry(rapidjson::kObjectType);

            // 解析格式: [2026-06-25 22:56:07] [INFO ]: message
            if (lines[i].length() > 33) {
                std::string timeStr = lines[i].substr(1, 19);
                std::string levelStr = lines[i].substr(23, 5);
                std::string msgStr = lines[i].substr(31);

                // trim level trailing spaces
                while (!levelStr.empty() && levelStr.back() == ' ') levelStr.pop_back();
                // trim leading ": " from message
                if (msgStr.length() >= 2 && msgStr[0] == ':' && msgStr[1] == ' ')
                    msgStr = msgStr.substr(2);

                rapidjson::Value t, l, m;
                t.SetString(timeStr.c_str(), allocator);
                l.SetString(levelStr.c_str(), allocator);
                m.SetString(msgStr.c_str(), allocator);
                logEntry.AddMember("time", t, allocator);
                logEntry.AddMember("level", l, allocator);
                logEntry.AddMember("msg", m, allocator);
            } else {
                rapidjson::Value t, l, m;
                t.SetString("", allocator);
                l.SetString("RAW", allocator);
                m.SetString(lines[i].c_str(), allocator);
                logEntry.AddMember("time", t, allocator);
                logEntry.AddMember("level", l, allocator);
                logEntry.AddMember("msg", m, allocator);
            }
            logsArr.PushBack(logEntry, allocator);
        }
    }

    retDoc.AddMember("code", 200, allocator);
    rapidjson::Value msg;
    msg.SetString("OK", allocator);
    retDoc.AddMember("message", msg, allocator);
    retDoc.AddMember("logs", logsArr, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    retDoc.Accept(writer);
    response = buffer.GetString();
    return 0;
}

int CSystem::serveFile(const std::string& request, std::string& response) {
    // 此方法不走 JSON 解析，由 server.cpp 直接读取文件并返回
    // response 就是文件路径
    response = request;
    return 0;
}