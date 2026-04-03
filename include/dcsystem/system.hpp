#include <string>
#include <unordered_map>
#include <DpfsApiDf.hpp>

struct CRiskInfo {
    std::string riskLevel;
    std::string riskReason;

};

struct initSystemInfo {
    std::string systemName;
    std::string systemVersion;
    std::string apiKey;
    std::string connStr;
};

class CSystem {
public:
    CSystem();
    ~CSystem();
    int init(const initSystemInfo& initInfo);
    /*
        @param request the json string like { "username": "john", "password": "secret" }
        @param response the json string like { "code": 0, "message": "Login successful", "user_token": 123 }
        @return 0 if success
    */
    int login(const std::string& request, std::string& response);

    /*
        @param request the json string like { "user_token": 123 }
        @param response the json string like { "code": 0, "message": "Logoff successful" }
        @return 0 if success
    */
    int logout(const std::string& request, std::string& response);

    /*
        TODO: fill in the comments for the following APIs
    */
    int listTracablePro(const std::string& request, std::string& response);
    // int listTables(const std::string& request, std::string& response);
    int risk(const std::string& request, std::string& response);
    int traceBack(const std::string& request, std::string& response);
    /*
        @note list one production basic info
    */
    int listProBasic(const std::string& request, std::string& response);
    int makeTrade(const std::string& request, std::string& response);

    int listRiskPro(const std::string& request, std::string& response);
private:

    // <user_token, dpfsclient>
    std::mutex user_tokens_mutex;
    int64_t usr_token = 0;
    std::unordered_map<int64_t, CGrpcCli> user_tokens;

    int checkUserToken(const int64_t& user_token, CGrpcCli*& client);
    int generateRiskReport(const CGrpcCli::CResult& result, std::string& risk_info, CGrpcCli& client);
    // 路径中如果某个配料存在安全风险，则整个产品都存在安全风险，可以快速标记该产品是否合规。
    int recursiveTrace(const std::string& trace_code, CGrpcCli& client, std::string& result, std::string indent, void* tDoc = nullptr, void* parentDoc = nullptr);
};
