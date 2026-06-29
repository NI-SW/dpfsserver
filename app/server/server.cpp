
#define CROW_USE_BOOST
// CRA build puts assets under static/static/; point Crow's static dir there
#define CROW_STATIC_DIRECTORY "static/static/"
#include <crow.h>
#include <iostream>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <dcsystem/system.hpp>
#include <log/logbinary.h>
#include <fstream>
#include <sstream>
#include <iomanip>
initSystemInfo initInfo;
CSystem* sys = nullptr;
extern logrecord* dlog;

void Args_Error();
void Analy_Input(int argc, char** argv);

int main(int argc, char* argv[]) {


    initInfo.systemName = "dpfsserver";
    initInfo.systemVersion = "0.0.0.1";
    initInfo.apiKey = "";
    initInfo.connStr = "127.0.0.1:20500";
    initInfo.mysqlHost     = "127.0.0.1";
    initInfo.mysqlPort     = 3306;
    initInfo.mysqlUser     = "root";
    initInfo.mysqlPasswd   = "";
    initInfo.mysqlDatabase = "dpfs";

    Analy_Input(argc, argv);

    sys = new CSystem();
    sys->init(initInfo);
    crow::SimpleApp app;

#define __LOGIN_API__
    CROW_ROUTE(app, "/api/login")
        .methods("POST"_method)([](const crow::request& req) {
            // get json string
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->login(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });
    
#define __REGISTER_API__
    CROW_ROUTE(app, "/api/register")
        .methods("POST"_method)([](const crow::request& req) {
            int rc = 0;
            std::cout << "Received register request: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->registerUser(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __LOGOUT_API__
    CROW_ROUTE(app, "/api/logout")
        .methods("POST"_method)([](const crow::request& req) {
            // get json string
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->logout(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __LIST_TRACEABLE_PRO_API__
    CROW_ROUTE(app, "/api/list_tracable_pro")
        .methods("POST"_method)([](const crow::request& req) {
            // get json string
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->listTracablePro(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __DROP_TRACEABLE_PRO_API__
    CROW_ROUTE(app, "/api/drop_tracable_pro")
        .methods("POST"_method)([](const crow::request& req) {
            // get json string
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->dropTracablePro(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __RISK_API__
    CROW_ROUTE(app, "/api/risk")
        .methods("POST"_method)([](const crow::request& req) {
            // get json string
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->risk(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __TRACE_BACK_API__
    CROW_ROUTE(app, "/api/trace_back")
        .methods("POST"_method)([](const crow::request& req) {
            // get json string
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->traceBack(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __MAKE_TRADE_API__
    CROW_ROUTE(app, "/api/make_trade")
        .methods("POST"_method)([](const crow::request& req) {
            // get json string
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->makeTrade(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });
        
#define __LIST_PRO_BASIC_API__
    CROW_ROUTE(app, "/api/list_pro_basic")
        .methods("POST"_method)([](const crow::request& req) {
            // get json string
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->listProBasic(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __LIST_RISK_PRO_API__
    CROW_ROUTE(app, "/api/list_risk_pro")
        .methods("POST"_method)([](const crow::request& req) {
            // get json string
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->listRiskPro(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __USER_INFO_API__
    CROW_ROUTE(app, "/api/user_info")
        .methods("POST"_method)([](const crow::request& req) {
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->getUserInfo(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __UPDATE_PASSWORD_API__
    CROW_ROUTE(app, "/api/update_password")
        .methods("POST"_method)([](const crow::request& req) {
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->updatePassword(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __UPDATE_USER_INFO_API__
    CROW_ROUTE(app, "/api/update_user_info")
        .methods("POST"_method)([](const crow::request& req) {
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->updateUserInfo(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __UPLOAD_FILE_API__
    CROW_ROUTE(app, "/api/upload")
        .methods("POST"_method)([](const crow::request& req) {
            int rc = 0;
            std::cout << "Received upload request, body size: " << req.body.size() << std::endl;
            std::string msg = "";
            rc = sys->uploadFile(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __LIST_FILES_API__
    CROW_ROUTE(app, "/api/list_files")
        .methods("POST"_method)([](const crow::request& req) {
            int rc = 0;
            std::cout << "Received list_files request: " << req.body << std::endl;
            std::string msg = "";
            rc = sys->listFiles(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

#define __MONITOR_API__
    CROW_ROUTE(app, "/api/monitor")
        .methods("POST"_method)([](const crow::request& req) {
            int rc = 0;
            std::string msg = "";
            rc = sys->monitor(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

    // 系统日志：POST /api/logs
    CROW_ROUTE(app, "/api/logs")
        .methods("POST"_method)([](const crow::request& req) {
            int rc = 0;
            std::string msg = "";
            rc = sys->getLogs(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

    // 提供文件访问：GET /api/serve_file?path=...
    CROW_ROUTE(app, "/api/serve_file")
        .methods("GET"_method)([](const crow::request& req) {
            auto pathIt = req.url_params.get("path");
            if (!pathIt) {
                return crow::response(400, "Missing 'path' parameter");
            }
            std::string filePath(pathIt);

            // 安全检查：只允许访问 uploads 目录
            if (filePath.find("/home/dpfs/github/dpfsserver/uploads/") != 0 || filePath.find("..") != std::string::npos) {
                return crow::response(403, "Access denied");
            }

            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                return crow::response(404, "File not found");
            }

            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            file.close();

            auto res = crow::response(content);

            // 提取文件名
            std::string filename = filePath;
            size_t lastSlash = filePath.rfind('/');
            if (lastSlash != std::string::npos) filename = filePath.substr(lastSlash + 1);

            // RFC 5987 编码：将非 ASCII 文件名正确编码，避免代理/浏览器乱码
            auto urlEncodeFilename = [](const std::string& s) -> std::string {
                std::ostringstream escaped;
                for (unsigned char c : s) {
                    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                        escaped << c;
                    } else {
                        escaped << '%' << std::uppercase << std::setw(2) << std::setfill('0') << std::hex << (int)c;
                    }
                }
                return escaped.str();
            };

            // 根据扩展名设置 MIME type
            std::string ext;
            size_t dot = filePath.rfind('.');
            if (dot != std::string::npos) ext = filePath.substr(dot);

            if (ext == ".mp4")  res.set_header("Content-Type", "video/mp4");
            else if (ext == ".webm") res.set_header("Content-Type", "video/webm");
            else if (ext == ".avi")  res.set_header("Content-Type", "video/x-msvideo");
            else if (ext == ".mov")  res.set_header("Content-Type", "video/quicktime");
            else if (ext == ".mp3")  res.set_header("Content-Type", "audio/mpeg");
            else if (ext == ".wav")  res.set_header("Content-Type", "audio/wav");
            else if (ext == ".jpg" || ext == ".jpeg") res.set_header("Content-Type", "image/jpeg");
            else if (ext == ".png")  res.set_header("Content-Type", "image/png");
            else if (ext == ".gif")  res.set_header("Content-Type", "image/gif");
            else if (ext == ".pdf")  res.set_header("Content-Type", "application/pdf");
            else if (ext == ".docx") res.set_header("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
            else if (ext == ".doc")  res.set_header("Content-Type", "application/msword");
            else if (ext == ".xlsx") res.set_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            else if (ext == ".txt")  res.set_header("Content-Type", "text/plain; charset=utf-8");
            else res.set_header("Content-Type", "application/octet-stream");

            res.set_header("Accept-Ranges", "bytes");
            // RFC 5987: 用 filename*=UTF-8''... 编码非 ASCII 文件名，兼容代理转发
            std::string encodedName = urlEncodeFilename(filename);
            res.set_header("Content-Disposition", "attachment; filename=\"" + encodedName + "\"; filename*=UTF-8''" + encodedName);
            return res;
        });

        
    // Serve index.html for root route (SPA entry point)
    CROW_ROUTE(app, "/")
        .methods("GET"_method)([]() {
            std::string indexPath = "/home/dpfs/github/dpfsserver/app/server/static/index.html";
            std::ifstream file(indexPath, std::ios::binary);
            if (!file.is_open()) {
                return crow::response(404, "Frontend not deployed");
            }
            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            auto res = crow::response(content);
            res.set_header("Content-Type", "text/html");
            return res;
        });

    // Serve other static root files (favicon, manifest, robots.txt, etc.)
    CROW_ROUTE(app, "/<string>")
        .methods("GET"_method)([](std::string filename) {
            // Don't intercept API routes
            if (filename.find("api") == 0) return crow::response(404);
            std::string filePath = "/home/dpfs/github/dpfsserver/app/server/static/" + filename;
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                // Fallback to index.html for SPA client-side routing
                std::string indexPath = "/home/dpfs/github/dpfsserver/app/server/static/index.html";
                std::ifstream indexFile(indexPath, std::ios::binary);
                if (!indexFile.is_open()) {
                    return crow::response(404, "File not found");
                }
                std::string content((std::istreambuf_iterator<char>(indexFile)),
                                    std::istreambuf_iterator<char>());
                auto res = crow::response(content);
                res.set_header("Content-Type", "text/html");
                return res;
            }
            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            std::string contentType = "application/octet-stream";
            if (filename.find(".png") != std::string::npos) contentType = "image/png";
            else if (filename.find(".ico") != std::string::npos) contentType = "image/x-icon";
            else if (filename.find(".json") != std::string::npos) contentType = "application/json";
            auto res = crow::response(content);
            res.set_header("Content-Type", contentType);
            return res;
        });

    app.port(20510).multithreaded().run();

    delete sys;
    sys = nullptr;
    delete dlog;
    dlog = nullptr;
    return 0;
}

void Args_Error()
{
    cout << "\tThe args begin with:\n" <<
        "\t--ak              [ai api key]\n" <<
        "\t--connStr         [dpfs server connection string]\n" <<
        "\t--mysqlHost       [MySQL host, default 127.0.0.1]\n" <<
        "\t--mysqlPort       [MySQL port, default 3306]\n" <<
        "\t--mysqlUser       [MySQL user, default root]\n" <<
        "\t--mysqlPasswd     [MySQL password]\n" <<
        "\t--mysqlDatabase   [MySQL database, default dpfs]\n" << endl;

}


void Analy_Input(int argc, char** argv) {
    vector<string> Input;
    if (argc <= 1) {
        cout << "missing args,exit" << endl;
        Args_Error();
        exit(99);
    }

    // if (argc % 2 == 0) {
    //     cout << "missing args,exit" << endl;
    //     Args_Error();
    //     exit(99);
    // }

    for (int i = 0; i < argc; i++)
    {
        Input.emplace_back(argv[i]);
    }

    for (int i = 1; i < argc;)
    {

        if (Input[i] == "--ak") {
            initInfo.apiKey = Input[i + 1];
            i += 2;
        } else if (Input[i] == "--connStr") {
            initInfo.connStr = Input[i + 1];
            i += 2;
        } else if (Input[i] == "--mysqlHost") {
            initInfo.mysqlHost = Input[i + 1];
            i += 2;
        } else if (Input[i] == "--mysqlPort") {
            initInfo.mysqlPort = std::stoi(Input[i + 1]);
            i += 2;
        } else if (Input[i] == "--mysqlUser") {
            initInfo.mysqlUser = Input[i + 1];
            i += 2;
        } else if (Input[i] == "--mysqlPasswd") {
            initInfo.mysqlPasswd = Input[i + 1];
            i += 2;
        } else if (Input[i] == "--mysqlDatabase") {
            initInfo.mysqlDatabase = Input[i + 1];
            i += 2;
        } else {
            cout << "missing args,exit" << endl;
            Args_Error();
            exit(99);
        }
    }
}

