#include <iostream>
#include <string>
#include <curl/curl.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

// 回调函数：接收 HTTP 响应数据
static size_t DeepSeekWriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    std::string *response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

// DeepSeek API 调用类（兼容 OpenAI 接口格式）
class DeepSeekClient {
public:
    DeepSeekClient(const std::string& apiKey,
                   const std::string& baseUrl = "https://api.deepseek.com/v1",
                   const std::string& model = "deepseek-reasoner")
        : apiKey_(apiKey), baseUrl_(baseUrl), model_(model) {}

    // 发送非流式对话请求
    std::string Chat(const std::string& userMessage) {
        CURL* curl = curl_easy_init();
        if (!curl) return "Error: Failed to initialize curl";

        // 构建 JSON 请求体
        rapidjson::Document doc;
        doc.SetObject();
        auto& allocator = doc.GetAllocator();

        // 添加 model
        doc.AddMember("model", rapidjson::Value(model_.c_str(), allocator), allocator);

        // 添加 messages
        rapidjson::Value messages(rapidjson::kArrayType);
        rapidjson::Value message(rapidjson::kObjectType);
        message.AddMember("role", "user", allocator);
        message.AddMember("content", rapidjson::Value(userMessage.c_str(), allocator), allocator);
        messages.PushBack(message, allocator);
        doc.AddMember("messages", messages, allocator);

        // 可选参数
        doc.AddMember("temperature", 1.0, allocator);
        doc.AddMember("max_tokens", 8192, allocator);
        doc.AddMember("stream", false, allocator);

        // 序列化为字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);
        std::string postData = buffer.GetString();

        // 设置请求头
        struct curl_slist* headers = nullptr;
        if (!apiKey_.empty()) {
            headers = curl_slist_append(headers, ("Authorization: Bearer " + apiKey_).c_str());
        }
        headers = curl_slist_append(headers, "Content-Type: application/json");

        std::string url = baseUrl_ + "/chat/completions";
        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DeepSeekWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // 按环境需要调整
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);       // 120 秒超时（推理模型较慢）

        CURLcode res = curl_easy_perform(curl);

        // 清理
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            return "Error: " + std::string(curl_easy_strerror(res));
        }

        // 解析 JSON 响应
        rapidjson::Document respDoc;
        if (respDoc.Parse(response.c_str()).HasParseError()) {
            return "Error: Failed to parse JSON response";
        }

        if (respDoc.HasMember("error") && respDoc["error"].IsObject()) {
            const auto& err = respDoc["error"];
            std::string errMsg = err.HasMember("message") ? err["message"].GetString() : "Unknown error";
            return "API Error: " + errMsg;
        }

        if (respDoc.HasMember("choices") && respDoc["choices"].IsArray() && respDoc["choices"].Size() > 0) {
            const auto& choice = respDoc["choices"][0];
            if (choice.HasMember("message") && choice["message"].HasMember("content")) {
                return choice["message"]["content"].GetString();
            }
        }

        return "Error: Unexpected response format";
    }

    // 发送带 system prompt 的对话请求
    std::string ChatWithSystem(const std::string& systemPrompt, const std::string& userMessage) {
        CURL* curl = curl_easy_init();
        if (!curl) return "Error: Failed to initialize curl";

        rapidjson::Document doc;
        doc.SetObject();
        auto& allocator = doc.GetAllocator();

        doc.AddMember("model", rapidjson::Value(model_.c_str(), allocator), allocator);

        rapidjson::Value messages(rapidjson::kArrayType);

        // system message
        rapidjson::Value sysMsg(rapidjson::kObjectType);
        sysMsg.AddMember("role", "system", allocator);
        sysMsg.AddMember("content", rapidjson::Value(systemPrompt.c_str(), allocator), allocator);
        messages.PushBack(sysMsg, allocator);

        // user message
        rapidjson::Value userMsg(rapidjson::kObjectType);
        userMsg.AddMember("role", "user", allocator);
        userMsg.AddMember("content", rapidjson::Value(userMessage.c_str(), allocator), allocator);
        messages.PushBack(userMsg, allocator);

        doc.AddMember("messages", messages, allocator);
        doc.AddMember("temperature", 1.0, allocator);
        doc.AddMember("max_tokens", 8192, allocator);
        doc.AddMember("stream", false, allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);
        std::string postData = buffer.GetString();

        struct curl_slist* headers = nullptr;
        if (!apiKey_.empty()) {
            headers = curl_slist_append(headers, ("Authorization: Bearer " + apiKey_).c_str());
        }
        headers = curl_slist_append(headers, "Content-Type: application/json");

        std::string url = baseUrl_ + "/chat/completions";
        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DeepSeekWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);

        CURLcode res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            return "Error: " + std::string(curl_easy_strerror(res));
        }

        rapidjson::Document respDoc;
        if (respDoc.Parse(response.c_str()).HasParseError()) {
            return "Error: Failed to parse JSON response";
        }

        if (respDoc.HasMember("error") && respDoc["error"].IsObject()) {
            const auto& err = respDoc["error"];
            std::string errMsg = err.HasMember("message") ? err["message"].GetString() : "Unknown error";
            return "API Error: " + errMsg;
        }

        if (respDoc.HasMember("choices") && respDoc["choices"].IsArray() && respDoc["choices"].Size() > 0) {
            const auto& choice = respDoc["choices"][0];
            if (choice.HasMember("message") && choice["message"].HasMember("content")) {
                return choice["message"]["content"].GetString();
            }
        }

        return "Error: Unexpected response format";
    }

    // 发送对话请求并返回完整 JSON 响应（含 usage 等元信息）
    std::string ChatRaw(const std::string& userMessage) {
        CURL* curl = curl_easy_init();
        if (!curl) return "{\"error\": \"Failed to initialize curl\"}";

        rapidjson::Document doc;
        doc.SetObject();
        auto& allocator = doc.GetAllocator();

        doc.AddMember("model", rapidjson::Value(model_.c_str(), allocator), allocator);

        rapidjson::Value messages(rapidjson::kArrayType);
        rapidjson::Value message(rapidjson::kObjectType);
        message.AddMember("role", "user", allocator);
        message.AddMember("content", rapidjson::Value(userMessage.c_str(), allocator), allocator);
        messages.PushBack(message, allocator);
        doc.AddMember("messages", messages, allocator);

        doc.AddMember("temperature", 1.0, allocator);
        doc.AddMember("max_tokens", 8192, allocator);
        doc.AddMember("stream", false, allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);
        std::string postData = buffer.GetString();

        struct curl_slist* headers = nullptr;
        if (!apiKey_.empty()) {
            headers = curl_slist_append(headers, ("Authorization: Bearer " + apiKey_).c_str());
        }
        headers = curl_slist_append(headers, "Content-Type: application/json");

        std::string url = baseUrl_ + "/chat/completions";
        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DeepSeekWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);

        CURLcode res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            return "{\"error\": \"" + std::string(curl_easy_strerror(res)) + "\"}";
        }

        return response;
    }

    // 查询可用模型列表
    std::string ListModels() {
        CURL* curl = curl_easy_init();
        if (!curl) return "Error: Failed to initialize curl";

        struct curl_slist* headers = nullptr;
        if (!apiKey_.empty()) {
            headers = curl_slist_append(headers, ("Authorization: Bearer " + apiKey_).c_str());
        }

        std::string url = baseUrl_ + "/models";
        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DeepSeekWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        CURLcode res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            return "Error: " + std::string(curl_easy_strerror(res));
        }

        return response;
    }

    // 设置模型名称
    void SetModel(const std::string& model) {
        model_ = model;
    }

    // 设置基础 URL
    void SetBaseUrl(const std::string& baseUrl) {
        baseUrl_ = baseUrl;
    }

    // 获取当前模型名称
    std::string GetModel() const {
        return model_;
    }

    // 获取当前基础 URL
    std::string GetBaseUrl() const {
        return baseUrl_;
    }

private:
    std::string apiKey_;
    std::string baseUrl_;
    std::string model_;
};
