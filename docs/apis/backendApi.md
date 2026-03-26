
## 溯源数据管理系统

# base on Data Partitioned Foodtrace System

# URL
```
/api/login
```

# METHOD
```
POST
```
# Request
parameter                 | type
------------------------- | ----------------------------------
username                  | String
password                  | String
# Response
parameter                 | type
------------------------- | ----------------------------------
code                      | Number
message                   | String
usertoken                 | Number


# URL
```
/api/logout
```
# METHOD
```
POST
```
# Request
parameter                 | type
------------------------- | ----------------------------------
usertoken                 | String
# Response
parameter                 | type
------------------------- | ----------------------------------
code                      | Number
message                   | String


# URL
```
/api/risk
```
# METHOD
```
POST
```
# Request
parameter                 | type
------------------------- | ----------------------------------
usertoken                 | Number
schema                    | String
proName                   | String
proNumber                 | Number
ingredients               | List of (String, String) pairs
baseInfo                  | List of (String, String) pairs

# Response
parameter                 | type
------------------------- | ----------------------------------
code                      | Number
message                   | String
riskInfo                  | String



/listTracablePro       =>列出全部可溯源组 
json {
	code: 0 ,
	message : "",
	tabList [
		"",
		"",
		""
	]
}



https://<ip>/risk     =》 风险评估


/listTracablePro       =>列出全部可溯源组 
json {
	code: 0 ,
	message : "",
	tabList [
		"",
		"",
		""
	]
}
/listTables                 =>列出系统内全部表


await fetch('http://localhost:8080/api/logout', { 
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: "admin" }) 
    });
算了，你把登出接口也写进去吧，保持完整性
@app.post("/api/logout")
def logout(item: dict):
    username = item.get("username")
    print(f"用户 {username} 已安全退出系统")
    return {"success": True}