#ifndef EXTRACTMODEL_EXTRACT_HPP
#define EXTRACTMODEL_EXTRACT_HPP

#include <iostream>
#include <string>
#include <sstream>
#include <curl/curl.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#include <cstdint>

// 去除非法 UTF-8 字节，保留合法字符（防御性清洗）
static std::string SanitizeUtf8(const std::string& input) {
    std::string result;
    result.reserve(input.size());
    size_t i = 0;
    while (i < input.size()) {
        uint8_t c = static_cast<uint8_t>(input[i]);
        int len = 0;
        if (c <= 0x7F)       { len = 1; }
        else if ((c & 0xE0) == 0xC0) { len = 2; }
        else if ((c & 0xF0) == 0xE0) { len = 3; }
        else if ((c & 0xF8) == 0xF0) { len = 4; }
        else { ++i; continue; } // 非法起始字节，跳过
        if (i + len > input.size()) break;
        bool valid = true;
        for (int j = 1; j < len; ++j) {
            if ((static_cast<uint8_t>(input[i + j]) & 0xC0) != 0x80) {
                valid = false; break;
            }
        }
        if (valid) { result.append(input, i, len); i += len; }
        else       { ++i; }
    }
    return result;
}

// 流式回调上下文
struct StreamContext {
    std::string fullContent;        // 累积的完整内容
    int completionTokens;           // 累积的 completion token 数（估算）
    bool truncated;                 // 是否被截断（token 过长）
    std::string chunkBuffer;        // SSE chunk 缓冲（处理不完整行）
    static const int MAX_TOKENS = 2048;

    StreamContext() : completionTokens(0), truncated(false) {}
};

// 粗略估算 token 数：中文约 1.5 token/字，英文约 0.75 token/word
// 采用保守估算：每 2 个字符约 1 个 token
static int EstimateTokens(const std::string& text) {
    return static_cast<int>(text.size() / 2) + 1;
}

// 回调函数：接收非流式 HTTP 响应数据
static size_t ExtractWriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    std::string *response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

// 流式回调函数：逐块接收 SSE 数据
static size_t ExtractStreamCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    StreamContext *ctx = static_cast<StreamContext*>(userp);
    std::string chunk(static_cast<char*>(contents), totalSize);
    ctx->chunkBuffer += chunk;

    // 按行处理 SSE 数据
    size_t pos = 0;
    while (pos < ctx->chunkBuffer.size()) {
        size_t lineEnd = ctx->chunkBuffer.find('\n', pos);
        if (lineEnd == std::string::npos) break; // 行不完整，等下一块

        std::string line = ctx->chunkBuffer.substr(pos, lineEnd - pos);
        pos = lineEnd + 1;

        // SSE 数据行以 "data: " 开头
        if (line.substr(0, 6) != "data: ") continue;
        std::string data = line.substr(6);

        // 流结束标记
        if (data == "[DONE]") continue;

        // 解析 JSON
        rapidjson::Document doc;
        if (doc.Parse(data.c_str()).HasParseError()) continue;

        // 检查错误
        if (doc.HasMember("error") && doc["error"].IsObject()) continue;

        // 提取增量内容
        if (doc.HasMember("choices") && doc["choices"].IsArray() && doc["choices"].Size() > 0) {
            const auto& choice = doc["choices"][0];
            if (choice.HasMember("delta") && choice["delta"].IsObject()) {
                const auto& delta = choice["delta"];
                if (delta.HasMember("content") && delta["content"].IsString()) {
                    std::string content = delta["content"].GetString();

                    // 检查 token 限制
                    int estimatedTokens = EstimateTokens(ctx->fullContent + content);
                    if (estimatedTokens > StreamContext::MAX_TOKENS) {
                        ctx->truncated = true;
                        return totalSize; // 停止接收
                    }

                    ctx->fullContent += content;
                    ctx->completionTokens = estimatedTokens;
                }
            }
        }
    }

    // 保留未处理完的部分
    ctx->chunkBuffer = ctx->chunkBuffer.substr(pos);
    return totalSize;
}

// 本地提取模型 API 调用类（基于 llama.cpp OpenAI 兼容接口）
class ExtractModelClient {
public:
    ExtractModelClient(const std::string& apiKey,
                       const std::string& baseUrl = "http://192.168.34.65:8080/v1",
                       const std::string& model = "qwen2.5-0.5B-Instruct-merged-model-ana")
        : apiKey_(apiKey), baseUrl_(baseUrl), model_(model), maxRetries_(3) {}

    // 内部通用流式请求方法
    // messages: rapidjson array of message objects
    std::string StreamChatInternal(rapidjson::Value& messages, rapidjson::Document::AllocatorType& allocator) {
        const int MAX_RETRIES = maxRetries_;

        for (int attempt = 0; attempt < MAX_RETRIES; ++attempt) {
            CURL* curl = curl_easy_init();
            if (!curl) return "Error: Failed to initialize curl";

            // 手动构建 JSON 请求体字符串，避免 AddMember 移动 messages
            rapidjson::Document doc;
            doc.SetObject();
            auto& alloc = doc.GetAllocator();

            doc.AddMember("model", rapidjson::Value(model_.c_str(), alloc), alloc);
            doc.AddMember("temperature", 0.7, alloc);
            doc.AddMember("max_tokens", StreamContext::MAX_TOKENS, alloc);
            doc.AddMember("stream", true, alloc);

            // 将 messages 深拷贝到 doc 中（使用 CopyFrom 而非构造函数，避免移动原值）
            rapidjson::Value msgCopy(rapidjson::kArrayType);
            msgCopy.CopyFrom(messages, alloc);
            doc.AddMember("messages", msgCopy, alloc);

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
            StreamContext ctx;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ExtractStreamCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L); // 流式请求给更长超时

            CURLcode res = curl_easy_perform(curl);

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);

            if (res != CURLE_OK) {
                return "Error: " + std::string(curl_easy_strerror(res));
            }

            // 如果没有截断，直接返回结果
            if (!ctx.truncated) {
                if (ctx.fullContent.empty()) {
                    return "Error: Empty response from model";
                }
                return ctx.fullContent;
            }

            // token 过长被截断，重新请求
            // 在重试前，给 messages 追加一条提示，要求模型更精简地输出
            if (attempt < MAX_RETRIES - 1) {
                rapidjson::Value retryMsg(rapidjson::kObjectType);
                retryMsg.AddMember("role", "user", allocator);

                std::string retryPrompt = "你上一次的回复过长被截断了。请用更简洁的方式重新输出，"
                    "字数控制在" + std::to_string(StreamContext::MAX_TOKENS * 2) +
                    "个字符以内，只保留最核心的信息，不要重复已有内容。";
                retryMsg.AddMember("content", rapidjson::Value(retryPrompt.c_str(), allocator), allocator);
                messages.PushBack(retryMsg, allocator);

                // 追加上一次的截断回复作为上下文
                rapidjson::Value assistantMsg(rapidjson::kObjectType);
                assistantMsg.AddMember("role", "assistant", allocator);
                assistantMsg.AddMember("content", rapidjson::Value(ctx.fullContent.c_str(), allocator), allocator);
                messages.PushBack(assistantMsg, allocator);
            }
        }

        // 重试耗尽，返回最后的结果
        return "Error: Model output exceeds token limit after " + std::to_string(MAX_RETRIES) + " retries";
    }

    // 发送流式对话请求（带 token 过长重试）
    std::string Chat(const std::string& userMessage) {
        rapidjson::Document doc;
        doc.SetObject();
        auto& allocator = doc.GetAllocator();

        std::string safeMessage = SanitizeUtf8(userMessage);

        rapidjson::Value messages(rapidjson::kArrayType);
        rapidjson::Value message(rapidjson::kObjectType);
        message.AddMember("role", "user", allocator);
        message.AddMember("content", rapidjson::Value(safeMessage.c_str(), allocator), allocator);
        messages.PushBack(message, allocator);

        return StreamChatInternal(messages, allocator);
    }

    // 发送带 system prompt 的流式对话请求（带 token 过长重试）
    std::string ChatWithSystem(const std::string& systemPrompt, const std::string& userMessage) {
        rapidjson::Document doc;
        doc.SetObject();
        auto& allocator = doc.GetAllocator();

        std::string safeSystem = SanitizeUtf8(systemPrompt);
        std::string safeUser   = SanitizeUtf8(userMessage);

        rapidjson::Value messages(rapidjson::kArrayType);

        // system message
        rapidjson::Value sysMsg(rapidjson::kObjectType);
        sysMsg.AddMember("role", "system", allocator);
        sysMsg.AddMember("content", rapidjson::Value(safeSystem.c_str(), allocator), allocator);
        messages.PushBack(sysMsg, allocator);

        // user message
        rapidjson::Value userMsg(rapidjson::kObjectType);
        userMsg.AddMember("role", "user", allocator);
        userMsg.AddMember("content", rapidjson::Value(safeUser.c_str(), allocator), allocator);
        messages.PushBack(userMsg, allocator);

        return StreamChatInternal(messages, allocator);
    }

    // 发送对话请求并返回完整 JSON 响应（含 usage、timings 等元信息）
    // 注意：此方法仍然使用非流式调用，因为需要完整的 JSON 元数据
    std::string ChatRaw(const std::string& userMessage) {
        CURL* curl = curl_easy_init();
        if (!curl) return "{\"error\": \"Failed to initialize curl\"}";

        std::string safeMessage = SanitizeUtf8(userMessage);

        rapidjson::Document doc;
        doc.SetObject();
        auto& allocator = doc.GetAllocator();

        doc.AddMember("model", rapidjson::Value(model_.c_str(), allocator), allocator);

        rapidjson::Value messages(rapidjson::kArrayType);
        rapidjson::Value message(rapidjson::kObjectType);
        message.AddMember("role", "user", allocator);
        message.AddMember("content", rapidjson::Value(safeMessage.c_str(), allocator), allocator);
        messages.PushBack(message, allocator);
        doc.AddMember("messages", messages, allocator);

        doc.AddMember("temperature", 0.7, allocator);
        doc.AddMember("max_tokens", StreamContext::MAX_TOKENS, allocator);
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
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ExtractWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);

        CURLcode res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            return "{\"error\": \"" + std::string(curl_easy_strerror(res)) + "\"}";
        }

        return response;
    }

    // 非流式对话请求（返回纯文本内容，不返回完整 JSON）
    std::string ChatSync(const std::string& userMessage) {
        CURL* curl = curl_easy_init();
        if (!curl) return "Error: Failed to initialize curl";

        // 防御性清洗：确保发送到服务器的文本是合法 UTF-8
        std::string safeMessage = SanitizeUtf8(userMessage);

        rapidjson::Document doc;
        doc.SetObject();
        auto& allocator = doc.GetAllocator();

        doc.AddMember("model", rapidjson::Value(model_.c_str(), allocator), allocator);
        rapidjson::Value messages(rapidjson::kArrayType);
        rapidjson::Value msg(rapidjson::kObjectType);
        msg.AddMember("role", "user", allocator);
        msg.AddMember("content", rapidjson::Value(safeMessage.c_str(), allocator), allocator);
        messages.PushBack(msg, allocator);
        doc.AddMember("messages", messages, allocator);
        doc.AddMember("temperature", 0.7, allocator);
        doc.AddMember("max_tokens", StreamContext::MAX_TOKENS, allocator);
        doc.AddMember("stream", false, allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);
        std::string postData = buffer.GetString();

        struct curl_slist* headers = nullptr;
        if (!apiKey_.empty()) {
            headers = curl_slist_append(headers, ("Authorization: *** " + apiKey_).c_str());
        }
        headers = curl_slist_append(headers, "Content-Type: application/json");

        std::string url = baseUrl_ + "/chat/completions";
        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ExtractWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            return "Error: " + std::string(curl_easy_strerror(res));
        }

        // 解析响应，提取 content
        rapidjson::Document respDoc;
        if (respDoc.Parse(response.c_str()).HasParseError()) {
            // JSON 解析失败（可能含非法 UTF-8），用字符串方式提取 content
            // 查找 "content":" 后的字符串内容
            size_t pos = response.find("\"content\":\"");
            if (pos != std::string::npos) {
                pos += 11; // skip "content":"
                size_t end = pos;
                // 找到字符串结束的引号（跳过转义的引号）
                while (end < response.size()) {
                    if (response[end] == '\\') { end += 2; continue; }
                    if (response[end] == '"') break;
                    end++;
                }
                return response.substr(pos, end - pos);
            }
            return "Error: Failed to parse response";
        }
        if (respDoc.HasMember("error") && respDoc["error"].IsObject()) {
            std::string errMsg = respDoc["error"].HasMember("message") ? respDoc["error"]["message"].GetString() : "Unknown error";
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
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ExtractWriteCallback);
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

    // 设置最大重试次数
    void SetMaxRetries(int retries) {
        maxRetries_ = retries;
    }

private:
    std::string apiKey_;
    std::string baseUrl_;
    std::string model_;
    int maxRetries_;
};

#endif // EXTRACTMODEL_EXTRACT_HPP
