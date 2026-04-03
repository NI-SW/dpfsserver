#include <dcsystem/system.hpp>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <deepseek/deepseek.hpp>
#include <fstream>

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

    std::string schema = doc["schema"].GetString();
    std::string product_name = doc["product_name"].GetString();

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
    rc = client->createTracablePro(
        schema,
        product_name,
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
            genResponseReturn(400, client->msg, response);
            return rc;
        }

        // judge risk level, if high, add the info to the risk table.
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
            rc = client->execSQL(sql);
            if (rc != 0) {
                genResponseReturn(400, client->msg, response);
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

int CSystem::recursiveTrace(const std::string& trace_code, CGrpcCli& client, std::string& result, std::string indent, void* tDoc, void* parentDoc) {
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
            
            ingredientInfoStr += indent + key + ": " + value + "\n";
            if (tDoc && parentDoc) {
                ingredientDoc.AddMember(
                    rapidjson::Value(key.c_str(), static_cast<rapidjson::Document*>(parentDoc)->GetAllocator()), 
                    rapidjson::Value(value.c_str(), static_cast<rapidjson::Document*>(parentDoc)->GetAllocator()), 
                    static_cast<rapidjson::Document*>(parentDoc)->GetAllocator());
            }
        }

        result += ingredientInfoStr;

        // if has child trace code, recursive trace child ingredient
        if (!childTraceCode.empty()) {
            // result += indent + "Tracing child ingredient with trace code: " + childTraceCode + "\n";
            rapidjson::Document childDoc;
            childDoc.SetObject();
            // cout << "trace back child ingredient with trace code: " << childTraceCode << endl;
            rc = recursiveTrace(childTraceCode, client, result, indent + "  ", &childDoc, parentDoc);
            if (rc == 0) {
                addObject(&ingredientDoc, "IngredientInfo", childDoc);
            }
        }
        
        if (tDoc && parentDoc) {
            ingArrayDoc.PushBack(ingredientDoc, static_cast<rapidjson::Document*>(parentDoc)->GetAllocator());
        }
    }
    
    addObject(tDoc, "IngredientInfo", ingArrayDoc);

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

/*
# Request
parameter                 | type                              | describe
------------------------- | ----------------------------------| ----------------------------------
user_token                | Number                            |
trace_code                | String (40 Bytes)                 |
trace_detail              | Number                            | 0 or 1, 是否返回详细交易信息
ingre_detail              | Number                            | 0 or 1, 是否返回详细配料信息
*/
int CSystem::traceBack(const std::string& request, std::string& response) {
    

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

    CGrpcCli* client = nullptr;
    this->checkUserToken(doc["user_token"].GetInt64(), client);
    if (client == nullptr) {
        genResponseReturn(400, "Invalid user token", response);
        return 400;
    }

    std::string tc = hex2Binary(doc["trace_code"].GetString());
    if (tc.size() != 20) {
        genResponseReturn(400, "Invalid trace code, must be 40 hex characters representing 20 bytes", response);
        return 400;
    }

    std::string trace_result;
    cout << "show detail : " << (bool)trace_defail << endl;
    rc = client->traceBack(tc, trace_result, trace_defail == 0 ? false : true);
    if (rc != 0) {
        genResponseReturn(rc, client->msg, response);
        return rc;
    }
    cout << "trace back result : " << trace_result << endl;

    CGrpcCli::CResult tresult;
    rc = client->parseTraceResult(trace_result, tresult);
    if (rc != 0) {
        genResponseReturn(rc, client->msg, response);
        return rc;
    }    
    std::string aiRiskStr = "";
    aiRiskStr.reserve(1024);
    std::vector<std::string> recursiveTraceCodes;
    recursiveTraceCodes.reserve(tresult.ingredient_info.size());

    // Base Info
    std::string traceBaseResult = "Base Info: {\n";
    traceBaseResult.reserve(512);
    for (const auto& [key, value] : tresult.base_info) {
        if (memcmp(key.c_str(), "ctime", 5) == 0) {
            // convert unix timestamp to human readable time
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

    // trade Info
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

    // ingredient Info
    std::string ingredientInfoStr = "Ingredient Info: {\n";
    ingredientInfoStr.reserve(1024);

    rapidjson::Document ingredientArrayDoc;
    ingredientArrayDoc.SetArray();
    
    for (const auto& ingredient : tresult.ingredient_info) {
        rapidjson::Document ingredientDoc;
        ingredientDoc.SetObject();
        for (const auto& [key, value] : ingredient.ingredient_info) {
            if (memcmp(key.c_str(), "Ingredient Trace Code", 21) == 0) {
                recursiveTraceCodes.emplace_back(value);
                continue;
            }
            ingredientInfoStr += key + ": " + value + "\n";
            // cout << "Adding ingredient info to document, key: " << key << ", value: " << value << endl;
            ingredientDoc.AddMember(
                rapidjson::Value(key.c_str(), tDoc.GetAllocator()),
                rapidjson::Value(value.c_str(), tDoc.GetAllocator()),
                tDoc.GetAllocator()
            );
        }
        if (ingDet == 1) {
            // cout << "recursive tracing this ingredient..." << endl;
            ingredientInfoStr += "child ingredient trace result: {\n";
            rapidjson::Document childDoc;
            childDoc.SetObject();
            int rc = recursiveTrace(recursiveTraceCodes.back(), *client, ingredientInfoStr, " ", &childDoc, &tDoc);
            if (rc != 0) {
                // ingredientInfoStr += "recursive trace failed for trace code: " + recursiveTraceCodes.back() + ", error code: " + std::to_string(rc) + ", message: " + client.msg + "\n";
            }
            ingredientInfoStr += "}\n";
            // Merge childDoc into tDoc
            ingredientDoc.AddMember(rapidjson::Value("IngredientInfo", tDoc.GetAllocator()), childDoc, tDoc.GetAllocator());
        }
        
        ingredientInfoStr += "-----------------\n";
        ingredientArrayDoc.PushBack(ingredientDoc, tDoc.GetAllocator());
    }
    tDoc.AddMember("ingredient_info", ingredientArrayDoc, tDoc.GetAllocator());
    // printDoc(tDoc);
    ingredientInfoStr += "}\n";

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


    rapidjson::Document retDoc;
    retDoc.SetObject();
    auto& allocator = retDoc.GetAllocator();
    retDoc.AddMember("code", 200, allocator);
    retDoc.AddMember("message", "", allocator);
    // std::string combinedResult = ; // traceBaseResult + traceTradeInfo + ingredientInfoStr;
    retDoc.AddMember("trace_result", rapidjson::Value(tDocStr.c_str(), allocator), allocator);
    retDoc.AddMember("ai_risk_report", rapidjson::Value(aiRiskStr.c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    retDoc.Accept(writer);
    response = buffer.GetString();



    return 0;
}

int CSystem::listProBasic(const std::string& request, std::string& response) {

    int rc = 0;
    const std::string& jsonStr = request;

    // create doc and parse json string
    rapidjson::Document doc;
    doc.Parse(jsonStr.c_str());
    rapidjson::Document retDoc;
    retDoc.SetObject();

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
    std::string schema = "";
    std::string name = "";

    rc = checkJsonFormat(doc, "user_token", jsonFieldType::IsInt64, response); if (rc != 0) { return rc; }
    rc = checkJsonFormat(doc, "schema", jsonFieldType::IsString, response); if (rc == 0) { schema = doc["schema"].GetString(); }
    rc = checkJsonFormat(doc, "name", jsonFieldType::IsString, response); if (rc == 0) { name = doc["name"].GetString(); }




    CGrpcCli* client = nullptr;
    this->checkUserToken(doc["user_token"].GetInt64(), client);
    if (client == nullptr) {
        genResponseReturn(400, "Invalid user token", response);
        return 400;
    }

    // get info from pro_SPXXB table
    std::string spxxb = name + "_SPXXB";
    rc = client->getTableHandle(schema, spxxb);
    if (rc != 0) {
        genResponseReturn(rc, client->msg, response);
        return rc;
    }
    
    int32_t hidx = 0;
    std::vector<std::string> idxNames;
    // get data from begin
    rc = client->getIdxIter(idxNames, {}, hidx);
    if (rc != 0) {
        genResponseReturn(rc, client->msg, response);
        return rc;
    }


    rapidjson::Document basicInfoArrDoc;
    basicInfoArrDoc.SetArray();
    while (client->fetchNextRow(hidx) == 0) {
        // col[0] - > key
        // col[1] -> value
        rapidjson::Document basicInfoObj;
        basicInfoObj.SetObject();

        std::string oval = "";
        rc = client->getDataByIdxIter(hidx, 0, oval, dpfs_ctype_t::TYPE_STRING);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
        }
        if (memcmp(oval.c_str(), "SPKZB", 5) == 0 || 
            memcmp(oval.c_str(), "PLKZB", 5) == 0 ||
            memcmp(oval.c_str(), "SPJYB", 5) == 0) {
            // this is the trace code column, skip
            continue;
        }
        basicInfoObj.AddMember("key", rapidjson::Value(oval.c_str(), basicInfoArrDoc.GetAllocator()), basicInfoArrDoc.GetAllocator());

        rc = client->getDataByIdxIter(hidx, 1, oval, dpfs_ctype_t::TYPE_STRING);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
        }
        cout << "value: " << oval << endl;
        basicInfoObj.AddMember("value", rapidjson::Value(oval.c_str(), basicInfoArrDoc.GetAllocator()), basicInfoArrDoc.GetAllocator());

        basicInfoArrDoc.PushBack(basicInfoObj, basicInfoArrDoc.GetAllocator());
    }

    client->releaseIdxIter(hidx);
    client->releaseTableHandle();


    // get ingredient info from pro_PLKZB table
    std::string plkzb = name + "_PLKZB";
    rc = client->getTableHandle(schema, plkzb);
    if (rc != 0) {
        cout << "Get table handle failed for table: " << schema << "." << plkzb << ", error code: " << rc << ", message: " << client->msg << endl;
        genResponseReturn(rc, client->msg, response);
        return rc;
    }

    hidx = 0;
    idxNames.clear();
    // get data from begin
    rc = client->getIdxIter(idxNames, {}, hidx);
    if (rc != 0) {
        cout << "Get index iterator failed for table: " << schema << "." << plkzb << ", error code: " << rc << ", message: " << client->msg << endl;
        genResponseReturn(rc, client->msg, response);
        return rc;
    }

    const auto& colInfo = client->getColInfo(hidx);


    rapidjson::Document ingreInfoArrDoc;
    ingreInfoArrDoc.SetArray();
    while (client->fetchNextRow(hidx) == 0) {
        // col[0] - > key
        // col[1] -> value
        rapidjson::Document ingInfoObj;
        ingInfoObj.SetObject();

        std::string oval = "";
        // ing name
        rc = client->getDataByIdxIter(hidx, 0, oval);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
        }
        ingInfoObj.AddMember("ingre_name", rapidjson::Value(oval.c_str(), ingreInfoArrDoc.GetAllocator()), ingreInfoArrDoc.GetAllocator());

        // ing trace code prefix
        rc = client->getDataByIdxIter(hidx, 1, oval);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
        }
        std::string trace_code_prefix = toHexString((uint8_t*)oval.data(), oval.size());
        ingInfoObj.AddMember("trace_code_prefix", rapidjson::Value(trace_code_prefix.c_str(), ingreInfoArrDoc.GetAllocator()), ingreInfoArrDoc.GetAllocator());

        // ing percentage
        rc = client->getDataByIdxIter(hidx, 2, oval);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
        }

        {
            // convert decimal binary to string
            my_decimal dec;
            rc = binary2my_decimal(0, (const uchar*)oval.data(), &dec, colInfo[2].getDds().genLen, colInfo[2].getScale());
            if (rc != 0) {
                cout << "Convert binary to decimal failed, error code: " << rc << endl;
                return rc;
            }
            String decStr;
            rc = my_decimal2string(0, &dec, &decStr);
            if (rc != 0) {
                cout << "Convert decimal to string failed, error code: " << rc << endl;
                return rc;
            }
            ingInfoObj.AddMember("percentage", rapidjson::Value(decStr.ptr(), ingreInfoArrDoc.GetAllocator()), ingreInfoArrDoc.GetAllocator());
        }

        ingreInfoArrDoc.PushBack(ingInfoObj, ingreInfoArrDoc.GetAllocator());
    }
    client->releaseIdxIter(hidx);

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

int CSystem::makeTrade(const std::string& request, std::string& response) {

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

    CGrpcCli* client = nullptr;
    this->checkUserToken(doc["user_token"].GetInt64(), client);
    if (client == nullptr) {
        genResponseReturn(400, "Invalid user token", response);
        return 400;
    }


    rc = client->makeTrade(tradeSchema, tradeProductName, 999/*deprecated*/, tradeProductStartID, tradeProductNumber, buyer, buyerAddr, buyerPhone, seller, sellerAddr, sellerPhone, logisticsInfo, otherInfo, tradePrice);
    if (rc != 0) {
        cout << "Make trade failed, error code: " << rc << endl;
        cout << "Error message: " << client->msg << endl;
        genResponseReturn(400, client->msg, response);
        // return rc;
    } else {
        genResponseReturn(200, client->msg, response);
    }
    
    return 0;
}

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
    rc = client->getTableHandle("SYSDPFS", "SYSRISKWARNS"); 
    if (rc != 0) {
        genResponseReturn(rc, client->msg, response);
        return rc;
    }

    std::vector<std::string> idxCol;
    idxCol.emplace_back();
    idxCol[0].resize(8);
    memcpy(const_cast<char*>(idxCol[0].data()), &begin, sizeof(begin));
    IDXHANDLE hidx = 0;

    rc = client->getIdxIter({"RTID"}, idxCol, hidx);
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
    rapidjson::Document traceProArr;
    traceProArr.SetArray();
/*
    rc = sysriskwarns.addCol("SCHEMA",      dpfs_datatype_t::TYPE_CHAR,      64,   0, cf::NOT_NULL | cf::PRIMARY_KEY);              if (rc != 0) { goto errReturn; }
    rc = sysriskwarns.addCol("NAME",        dpfs_datatype_t::TYPE_CHAR,      64,   0, cf::NOT_NULL | cf::PRIMARY_KEY);              if (rc != 0) { goto errReturn; }
    rc = sysriskwarns.addCol("DESCRIPTION", dpfs_datatype_t::TYPE_CHAR,      2048, 0, cf::NOT_NULL);                                if (rc != 0) { goto errReturn; }
    rc = sysriskwarns.addCol("RTID",        dpfs_datatype_t::TYPE_BIGINT,    8,    0, cf::NOT_NULL | cf::UNIQUE |cf::AUTO_INC);     if (rc != 0) { goto errReturn; }
*/
    for (int i = 0; i < limit; ++i) {
        if (rc != 0) {
            break;
        }
        rapidjson::Document traceProObj;
        traceProObj.SetObject();

        std::string gval;
        rc = client->getDataByIdxIter(hidx, 0, gval);
        if (rc != 0) {
            genResponseReturn(rc, client->msg, response);
            return rc;
        }
        
        // convert gval from binary to hex string
        std::string schema(gval);

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

        rc = client->fetchNextRow(hidx);
        if (rc != 0) {
            break;
        }
    }

    docRet.AddMember("total", total, allocator);
    docRet.AddMember("pro_list", traceProArr, allocator);

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
