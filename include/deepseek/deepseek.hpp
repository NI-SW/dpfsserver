#include <iostream>
#include <string>
#include <curl/curl.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

// 回调函数：接收 HTTP 响应数据
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    std::string *response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

// DeepSeek API 调用类
class DeepSeekClient {
public:
    DeepSeekClient(const std::string& apiKey) : apiKey_(apiKey) {}

    // 发送非流式对话请求
    std::string Chat(const std::string& userMessage) {
        CURL* curl = curl_easy_init();
        if (!curl) return "Error: Failed to initialize curl";

        // 构建 JSON 请求体
        rapidjson::Document doc;
        doc.SetObject();
        auto& allocator = doc.GetAllocator();

        // 添加 model
        doc.AddMember("model", "deepseek-chat", allocator);
        
        // 添加 messages
        rapidjson::Value messages(rapidjson::kArrayType);
        rapidjson::Value message(rapidjson::kObjectType);
        message.AddMember("role", "user", allocator);
        message.AddMember("content", rapidjson::Value(userMessage.c_str(), allocator), allocator);
        messages.PushBack(message, allocator);
        doc.AddMember("messages", messages, allocator);

        // 可选参数
        doc.AddMember("temperature", 0.7, allocator);
        doc.AddMember("max_tokens", 2048, allocator);
        doc.AddMember("stream", false, allocator);

        // 序列化为字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);
        std::string postData = buffer.GetString();

        // 设置请求头
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, ("Authorization: Bearer " + apiKey_).c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");

        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.deepseek.com/chat/completions");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 生产环境建议启用

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
            // 处理 API 错误
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

private:
    std::string apiKey_;
};
