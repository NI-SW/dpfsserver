
## 溯源数据管理系统

# base on Data Partitioned Foodtrace System

# URL
```
/login
```

# METHOD
```
POST
```
# param
parameter                 | type
------------------------- | ----------------------------------
username                  | string
password                  | string

https://<ip>/logout =》 登出
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
