#include <dcsystem/system.hpp>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>


std::string connStr = "127.0.0.1:20500";

CSystem::CSystem() {

}

CSystem::~CSystem() {

}

int CSystem::init() {
    // std::string connStr = ip + ":" + port;
    // cout << "connecting to " << connStr << endl;

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
        response = "{\"code\":400,\"message\":\"" + std::string(rapidjson::GetParseError_En(doc.GetParseError())) + "\"}";
        return 400;
    }

    // 4. 验证根节点为对象
    if (!doc.IsObject()) {
        response = "{\"code\":400,\"message\":\"Root must be a JSON object\"}";
        return 400;
    }

    // 5. 提取字段并验证
    if (!doc.HasMember("username") || !doc["username"].IsString()) {
        response = "{\"code\":400,\"message\":\"Missing or invalid 'username' field\"}";
        return 400;
    }
    if (!doc.HasMember("password") || !doc["password"].IsString()) {
        response = "{\"code\":400,\"message\":\"Missing or invalid 'password' field\"}";
        return 400;
    }

    std::string username = doc["username"].GetString();
    std::string password = doc["password"].GetString();


    auto channel = grpc::CreateChannel(connStr, grpc::InsecureChannelCredentials());
    if (channel == nullptr) {
        cerr << "Failed to create gRPC channel" << endl;
        response = "{\"code\":500,\"message\":\"Connect to db error\"}";
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

        response = "{\"code\":" + to_string(rc) + ",\"message\":\"" + client.msg + "\"}";
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
        response = "{\"code\":\"400\",\"message\":\"" + std::string(rapidjson::GetParseError_En(doc.GetParseError())) + "\"}";
        return 400;
    }

    // 4. 验证根节点为对象
    if (!doc.IsObject()) {
        response = "{\"code\":400,\"message\":\"Root must be a JSON object\"}";
        return 400;
    }

    // 5. 提取字段并验证
    if (!doc.HasMember("user_token") || !doc["user_token"].IsInt64()) {
        response = "{\"code\":400,\"message\":\"Missing or invalid 'user_token' field\"}";
        return 400;
    }

    int64_t user_token = doc["user_token"].GetInt64();

    this->user_tokens_mutex.lock();
    auto it = user_tokens.find(user_token);
    if (it == user_tokens.end()) {
        this->user_tokens_mutex.unlock();
        response = "{\"code\":400,\"message\":\"Invalid user token\"}";
        return 400;
    }
    CGrpcCli& client = it->second;
    rc = client.logoff();
    if (rc == 0) {
        cout << "Logoff successful for user token: " << user_token << endl;
        response = "{\"code\":0,\"message\":\"Logoff successful\"}";
        user_tokens.erase(it);
    } else {
        cout << "Logoff failed for user token: " << user_token << ", error code: " << rc << endl;
        cout << "Error message: \n" << client.msg << endl;

        response = "{\"code\":" + to_string(rc) + ",\"message\":\"" + client.msg + "\"}";
    }
    this->user_tokens_mutex.unlock();

    return rc;
}