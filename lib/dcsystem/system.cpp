#include <dcsystem/system.hpp>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <deepseek/deepseek.hpp>
#include <fstream>
enum class jsonFieldType : uint8_t {
    IsString = 0,
    IsInt64,
    IsInt,
    IsArray,
    IsObject,
};

std::string g_connStr = "127.0.0.1:20500";
std::string g_apiKey = "";
std::string g_aiPromptTemplate = "";

CSystem::CSystem() {

}

CSystem::~CSystem() {

}

int CSystem::init(const initSystemInfo& initInfo) {
    // std::string g_connStr = ip + ":" + port;
    // cout << "connecting to " << g_connStr << endl;

    g_connStr = initInfo.connStr;
    g_apiKey = initInfo.apiKey;
    std::fstream promptFile("prompt", std::ios::in);
    if (!promptFile.is_open()) {
        return -EIO;
    }
    char buf[65535] {0};
    promptFile.read(buf, sizeof(buf) - 1);
    g_aiPromptTemplate = std::string(buf);
    promptFile.close();

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


    auto channel = grpc::CreateChannel(g_connStr, grpc::InsecureChannelCredentials());
    if (channel == nullptr) {
        cerr << "Failed to create gRPC channel" << endl;
        genResponseReturn(500, "Connect to db error", response);
        return 500;
    }


    this->user_tokens_mutex.lock();
    auto it = user_tokens.emplace(usr_token, channel);
    ++usr_token;
    this->user_tokens_mutex.unlock();

    CGrpcCli& client = it.first->second;
    rc = client.login(username, password);
    if (rc != 0) {
        cout << "Login failed for user: " << username << ", error code: " << rc << endl;
        cout << "Error message: \n" << client.msg << endl;
        genResponseReturn(rc, client.msg, response);
        return 500;
    } else {
        cout << "Login successful for user: " << username << endl;
        cout << "Message: \n" << client.msg << endl;
    }

    // use rapidjson construct json
    rapidjson::Document docResponse;
    docResponse.SetObject();
    auto& allocator = docResponse.GetAllocator();
    docResponse.AddMember("code", rc, allocator);
    docResponse.AddMember("message", rapidjson::Value(client.msg.c_str(), allocator), allocator);
    docResponse.AddMember("user_token", rapidjson::Value(it.first->first), allocator);

    // return json string
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    docResponse.Accept(writer);
    response = buffer.GetString();

    return 0;
}

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
    CGrpcCli& client = it->second;
    rc = client.logoff();
    if (rc == 0) {
        // cout << "Logoff successful for user token: " << user_token << endl;
        genResponseReturn(0, "Logoff successful", response);
        user_tokens.erase(it);
    } else {
        // cout << "Logoff failed for user token: " << user_token << ", error code: " << rc << endl;
        // cout << "Error message: \n" << client.msg << endl;
        genResponseReturn(rc, client.msg, response);
    }
    this->user_tokens_mutex.unlock();

    return rc;
}

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
    CGrpcCli* client = nullptr;
    rc = checkUserToken(user_token, client);
    if (rc != 0) {
        genResponseReturn(400, "Invalid user token", response);
        return 400;
    }
    if (client == nullptr) {
        genResponseReturn(400, "User token not found", response);
        return 400;
    }

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

    // get table handle
    rc = client->getTableHandle("SYSDPFS", "SYSTRACEABLES"); 
    if (rc != 0) {
        genResponseReturn(rc, client->msg, response);
        return rc;
    }

    std::vector<std::string> idxCol;
    idxCol.emplace_back();
    idxCol[0].resize(8);
    memcpy(const_cast<char*>(idxCol[0].data()), &begin, sizeof(begin));
    IDXHANDLE hidx = 0;

    rc = client->getIdxIter({"TID"}, idxCol, hidx);
    if (rc != 0) {
        if (rc == ENOENT) {
            // no more row to fetch, return empty result
            genResponseReturn(0, "No more traceable products", response);
            return 0;
        }
        genResponseReturn(rc, client->msg, response);
        return rc;
    }

    const auto& colInfo = client->getColInfo(hidx);
    size_t total = client->getTotalRowCount(hidx);
    // cout << "Total traceable products: " << total << endl;

    rc = client->fetchNextRow(hidx);
    if (rc != 0) {
        if (rc == ENOENT) {
            // no more row to fetch, return empty result
            genResponseReturn(0, "No more traceable products", response);
            return 0;
        }
        genResponseReturn(rc, client->msg, response);
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
    // cout << "Total traceable products: " << total << endl;
    rapidjson::Value traceProArr(rapidjson::kArrayType);
    for (int i = 0; i < limit; ++i) {
        if (rc != 0) {
            break;
        }

        std::string gval;
        rc = client->getDataByIdxIter(hidx, 0, gval);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
        }
        
        // convert gval from binary to hex string
        std::string trace_code_prefix = toHexString((uint8_t*)gval.data(), gval.size());

        rc = client->getDataByIdxIter(hidx, 1, gval);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
        }
        std::string product_name(gval);

        rc = client->getDataByIdxIter(hidx, 2, gval);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
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

        rc = client->fetchNextRow(hidx);
        if (rc != 0) {
            break;
        }
    }
    docRet.AddMember("total", total, allocator);
    docRet.AddMember("trace_pros", traceProArr, allocator);

    // cout << "Release table handle" << endl;
    rc = client->releaseIdxIter(hidx);
    if (rc != 0) {
        // genResponseReturn(rc, client->msg, response);
        // return rc;
    }

    // cout << "Release index iterator" << endl;
    rc = client->releaseTableHandle();
    if (rc != 0) {
        genResponseReturn(rc, client->msg, response);
        return rc;
    }



    docRet.AddMember("code", 200, allocator);
    docRet.AddMember("message", "", allocator);

    /*
{"user_token": 0, "begin": 0, "limit": 10}
    */
    
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    docRet.Accept(writer);
    response = buffer.GetString();

    return 0;

}


int CSystem::checkUserToken(const int64_t& user_token, CGrpcCli*& client) {
    
    this->user_tokens_mutex.lock();
    auto it = user_tokens.find(user_token);
    if (it == user_tokens.end()) {
        this->user_tokens_mutex.unlock();
        return -EINVAL;
    }
    client = &it->second;
    this->user_tokens_mutex.unlock();

    return 0;
}


/*
# 描述
```
创建溯源组，并生成风险评估报告
```
# URL
```
/api/risk
```
# METHOD
```
POST
```
# Request
parameter                 | type                               | describe
------------------------- | ---------------------------------- | ----------------------------------
user_token                | Number                             | 
schema                    | String                             | 
product_name              | String                             | 
product_number            | Number                             | 
ingredients               | List of (String, String) pairs     | 
base_info                 | List of (String, String) pairs     | 
risk_report               | Number                             | 指定是否生成评估报告, 0 or 1
# Response
parameter                 | type
------------------------- | ----------------------------------
code                      | Number
message                   | String
risk_info                 | String
# example
```
{
  "user_token": 0,
  "schema": "OOO",
  "product_name": "烧烤酱",
  "product_number": 10000,
  "ingredients": [
    ["鸡蛋", "50.00"],
    ["糖", "15.5"]，
    ["酱油", "34.5"]
  ],
  "base_info": [
    ["key", "value"],
    ["key", "value"]
  ]
}
```
*/
int CSystem::risk(const std::string& request, std::string& response) {
    // 替换为你的真实 API Key

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

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "schema", jsonFieldType::IsString, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "product_name", jsonFieldType::IsString, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "product_number", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "ingredients", jsonFieldType::IsArray, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "base_info", jsonFieldType::IsArray, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "risk_report", jsonFieldType::IsInt, response); if (rc != 0) { return rc; }

    CGrpcCli* client = nullptr;
    this->checkUserToken(doc["user_token"].GetInt64(), client);
    if (client == nullptr) {
        genResponseReturn(400, "Invalid user token", response);
        return 400;
    }

    // create pro
    std::map<std::string, std::string> ingredients;
    for (const auto& item : doc["ingredients"].GetArray()) {
        if (!item.IsArray() || item.Size() != 2 || !item[0].IsString() || !item[1].IsString()) {
            genResponseReturn(400, "Invalid 'ingredients' field, must be an array of (string, string) pairs", response);
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
    rc = client->createTracablePro(
        doc["schema"].GetString(),
        doc["product_name"].GetString(),
        base_info,
        ingredients,
        product_number,
        trace_code_prefix
    );
    if (rc != 0) {
        genResponseReturn(rc, client->msg, response);
        return rc;
    }
    
    if (risk_report == 1) {
        std::string trace_code;
        trace_code.resize(20);
        memcpy(trace_code.data(), trace_code_prefix.data(), 16);
        memset(trace_code.data() + 16, 0, 4);
        
        std::string trace_result;
        rc = client->traceBack(trace_code, trace_result, 0);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
        }

        cout << "trace back result : " << trace_result << endl;

        CGrpcCli::CResult result;
        rc = client->parseTraceResult(trace_result, result);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
        }

        // generate risk report
        std::string risk_info;
        rc = this->generateRiskReport(result, risk_info, *client);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
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
int CSystem::recursiveTrace(const std::string& trace_code, CGrpcCli& client, std::string& result, std::string indent) {
    int rc = 0;
    std::string trace_result;
    // trace current ingredient
    std::string tc = hex2Binary(trace_code);
    rc = client.traceBack(tc, trace_result, 0);
    if (rc != 0) {
        return rc;
    }
    // cout << "trace back result : " << trace_result << endl;
    CGrpcCli::CResult tresult;
    rc = client.parseTraceResult(trace_result, tresult);
    if (rc != 0) {
        return rc;
    }

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
    }
    result += ingredientBaseInfo;

    for (const auto& ingredient : tresult.ingredient_info) {
        std::string ingredientInfoStr = indent + "Ingredient Info:\n";
        std::string childTraceCode;
        for (const auto& [key, value] : ingredient.ingredient_info) {

            if (memcmp(key.c_str(), "Ingredient Trace Code", 21) == 0) {
                childTraceCode = value;
                continue;
            }
            ingredientInfoStr += indent + key + ": " + value + "\n";
        }
        result += ingredientInfoStr;

        if (!childTraceCode.empty()) {
            // result += indent + "Tracing child ingredient with trace code: " + childTraceCode + "\n";
            rc = recursiveTrace(childTraceCode, client, result, indent + "  ");
            if (rc != 0) {
                return rc;
            }
        }
    }

    return 0;
}


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
            // ingredientInfoStr += "recursive trace failed for trace code: " + recursiveTraceCodes.back() + ", error code: " + std::to_string(rc) + ", message: " + client.msg + "\n";
        }
        ingredientInfoStr += "}\n";
        
        ingredientInfoStr += "-----------------\n";
    }

    // ingredientInfoStr += "recursive trace infos: \n";


    // for (auto& trace_code : recursiveTraceCodes) {
    //     cout << "Tracing ingredient with trace code: " << trace_code << endl;
    //     int rc = recursiveTrace(trace_code, client, ingredientInfoStr);
    // }

    
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