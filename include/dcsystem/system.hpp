#include <string>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
// #include <DpfsApiDf.hpp>  // temporarily disabled for build
#include <dpfsclient/grpcclient.hpp>
#include <basic/dpfsconst.hpp>

struct CRiskInfo {
    std::string riskLevel;
    std::string riskReason;

};

struct MetaIngredient {
    std::string name;           // 元配料名
    double cumulativePercent;   // 相对根产品的累计占比 (如 0.25 表示 25%)
    double grams;               // 克数
};

struct initSystemInfo {
    std::string systemName;
    std::string systemVersion;
    std::string apiKey;
    std::string connStr;
    // MySQL RBAC 连接参数
    std::string mysqlHost     = "127.0.0.1";
    int         mysqlPort     = 3306;
    std::string mysqlUser     = "root";
    std::string mysqlPasswd   = "";
    std::string mysqlDatabase = "dpfs";
};

struct UserSession {
    int64_t  uid;
    std::string username;
    std::string role;
    std::unordered_set<std::string> permissions;
    std::shared_ptr<CGrpcCli> client;
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
    int dropTracablePro(const std::string& request, std::string& response);
    int risk(const std::string& request, std::string& response);
    int traceBack(const std::string& request, std::string& response);
    /*
        @note list one production basic info
    */
    int listProBasic(const std::string& request, std::string& response);
    int makeTrade(const std::string& request, std::string& response);

    int listRiskPro(const std::string& request, std::string& response);

    // 用户信息查询 & 修改密码 & 修改信息
    int getUserInfo(const std::string& request, std::string& response);
    int updatePassword(const std::string& request, std::string& response);
    int updateUserInfo(const std::string& request, std::string& response);

    // 用户注册（无需登录）
    int registerUser(const std::string& request, std::string& response);

    // 文件上传：保存到 <项目路径>/uploads/<schema>/<product_name>/<filename>
    int uploadFile(const std::string& request, std::string& response);

    // 列出产品下所有已上传文件
    int listFiles(const std::string& request, std::string& response);

    // 读取文件内容（用于前端播放/下载）
    int serveFile(const std::string& request, std::string& response);

private:

    // <user_token, UserSession>
    std::mutex user_tokens_mutex;
    int64_t usr_token = 0;
    std::unordered_map<int64_t, std::shared_ptr<UserSession>> user_tokens;

    // RBAC 权限校验
    int checkTokenAndPermission(int64_t user_token, const std::string& permCode, UserSession*& session);

    int generateRiskReport(const CGrpcCli::CResult& result, std::string& risk_info, CGrpcCli& client);
    // 路径中如果某个配料存在安全风险，则整个产品都存在安全风险，可以快速标记该产品是否合规。
    int recursiveTrace(const std::string& trace_code, CGrpcCli& client, std::string& result, std::string indent, void* tDoc = nullptr, void* parentDoc = nullptr, double parentProportion = 1.0, std::map<std::string, double>* metaIngredients = nullptr);
};