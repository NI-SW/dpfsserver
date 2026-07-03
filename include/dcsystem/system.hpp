#include <string>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
// #include <DpfsApiDf.hpp>  // temporarily disabled for build
#include <dpfsclient/grpcclient.hpp>
#include <basic/dpfsconst.hpp>
#include <log/logbinary.h>
#include "dcsystem/dpfs_pool.hpp"

// 全局日志实例
extern logrecord* dlog;

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
    std::chrono::steady_clock::time_point last_access;  // 最后操作时间

    UserSession() : uid(0), last_access(std::chrono::steady_clock::now()) {}
    void touch() { last_access = std::chrono::steady_clock::now(); }
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

    // 系统监控：总产品数、风险产品数、每分钟溯源查询次数、系统响应时间、系统报错、系统负载
    int monitor(const std::string& request, std::string& response);

    // 系统日志：返回 dserver.log 最近 N 行
    int getLogs(const std::string& request, std::string& response);

private:

    // 共享 gRPC 通道（所有用户复用同一连接，避免多连接导致 dpfs 后端崩溃）
    std::shared_ptr<grpc::Channel> dpfs_channel;
    // dpfs 连接池：复用预认证的 CGrpcCli，避免频繁 Login/Logoff 导致页面缓存错乱
    std::unique_ptr<DpfsConnectionPool> dpfs_pool;

    // <user_token, UserSession>
    std::mutex user_tokens_mutex;
    int64_t usr_token = 1;
    std::unordered_map<int64_t, std::shared_ptr<UserSession>> user_tokens;

    // RBAC 权限校验
    int checkTokenAndPermission(int64_t user_token, const std::string& permCode, UserSession*& session);

    // session 超时清理线程
    void sessionCleanupLoop();
    void sessionCleanup();
    std::thread session_cleanup_thread_;
    bool stop_session_cleanup_ = false;
    std::chrono::seconds session_timeout_{900};  // 15 分钟

    int generateRiskReport(const CGrpcCli::CResult& result, std::string& risk_info, CGrpcCli& client);
    // 从 MySQL 读取用户 description 字段（患者信息）
    std::string getUserDescription(int64_t uid);
    // 路径中如果某个配料存在安全风险，则整个产品都存在安全风险，可以快速标记该产品是否合规。
    int recursiveTrace(const std::string& trace_code, CGrpcCli& client, std::string& result, std::string indent, void* tDoc = nullptr, void* parentDoc = nullptr, double parentProportion = 1.0, std::map<std::string, double>* metaIngredients = nullptr);
};