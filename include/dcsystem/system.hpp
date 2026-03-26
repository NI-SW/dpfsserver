#include <string>
#include <unordered_map>
#include <DpfsApiDf.hpp>
#include <dpfsdebug.hpp>

struct CRiskInfo {
    std::string riskLevel;
    std::string riskReason;

};

class CSystem {
public:
    CSystem();
    ~CSystem();
    int init();
    int login(const std::string& request, std::string& response);
    int logout(const std::string& request, std::string& response);
    int listTracablePro(const std::string& request, std::string& response);
    int risk(const std::string& request, std::string& response);

private:

    // <user_token, dpfsclient>
    std::mutex user_tokens_mutex;
    int64_t usr_token = 0;
    std::unordered_map<int64_t, CGrpcCli> user_tokens;

};
