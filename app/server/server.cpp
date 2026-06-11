
#define CROW_USE_BOOST
#include <crow.h>
#include <iostream>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <dcsystem/system.hpp>
initSystemInfo initInfo;
CSystem sys;

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


    sys.init(initInfo);
    crow::SimpleApp app;

#define __LOGIN_API__
    CROW_ROUTE(app, "/api/login")
        .methods("POST"_method)([](const crow::request& req) {
            // get json string
            int rc = 0;
            std::cout << "Received JSON: " << req.body << std::endl;
            std::string msg = "";
            rc = sys.login(req.body, msg);
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
            rc = sys.logout(req.body, msg);
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
            rc = sys.listTracablePro(req.body, msg);
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
            rc = sys.risk(req.body, msg);
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
            rc = sys.traceBack(req.body, msg);
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
            rc = sys.makeTrade(req.body, msg);
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
            rc = sys.listProBasic(req.body, msg);
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
            rc = sys.listRiskPro(req.body, msg);
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
            rc = sys.getUserInfo(req.body, msg);
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
            rc = sys.updatePassword(req.body, msg);
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
            rc = sys.updateUserInfo(req.body, msg);
            if (rc != 0) {
                return crow::response(rc, msg);
            }
            auto res = crow::response(200, msg);
            return res;
        });

        
    app.port(20510).multithreaded().run();

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

