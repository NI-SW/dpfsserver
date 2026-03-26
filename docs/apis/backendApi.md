
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
user_token                | Number


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
user_token                | Number
# Response
parameter                 | type
------------------------- | ----------------------------------
code                      | Number
message                   | String

# 描述
```
创建溯源组，并生成风险评估报告
```
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
user_token                | Number
schema                    | String
product_name              | String
product_number            | Number
ingredients               | List of (String, String) pairs
base_info                 | List of (String, String) pairs
# Response
parameter                 | type
------------------------- | ----------------------------------
code                      | Number
message                   | String
risk_info                 | String
# example
```
{
  "user_token": 0,
  "schema": "OOO",
  "product_name": "烧烤酱",
  "product_number": 10000,
  "ingredients": [
    ["鸡蛋", "50.00"],
    ["糖", "15.5"]，
    ["酱油", "34.5"]
  ],
  "base_info": [
    ["key", "value"],
    ["key", "value"]
  ]
}
```

# 描述
```
列出可溯源结构列表
```
# URL
```
/api/list_tracable_pro
```
# METHOD
```
GET
```
# Request
parameter                 | type
------------------------- | ----------------------------------
user_token                | Number

# Response
parameter                 | type
------------------------- | ----------------------------------
code                      | Number
message                   | String
trace_pros                | Array of Objects

# example
```
json {
	code: 0 ,
	message : "",
	trace_pros : [
		{"group_name":"北京林业大学",product_name:"苹果派","trace_code_prefix":"00000000000000001D05000000000000"},
		{"group_name":"北京林业大学",product_name:"香蕉派","trace_code_prefix":"00000000000000001D09000000000000"},
		{"group_name":"北京林业大学",product_name:"草莓派","trace_code_prefix":"00000000000000001D01000000000000"}
	]
}
```


# 描述
```
根据表ID(TABLE_ID，系统表unique索引列)，列出系统内的表
```
# URL
```
/api/list_tables
```
# METHOD
```
GET
```
# Request
parameter                 | type                              | describe
------------------------- | ----------------------------------| ----------------------------------
user_token                | Number                            |
begin                     | Number                            | 提取表的起始ID
limit                     | Number                            | 提取表的数量

# Response
parameter                 | type
------------------------- | ----------------------------------
code                      | Number
message                   | String
table_list                | Array of Objects
# Array of table_list params
parameter                 | type                              | describe
------------------------- | ----------------------------------| ----------------------------------
schema_name               | String                            | 
table_name                | String                            |
create_time               | String                            |
key_cols                  | Number                            | 联合主键的数量
TABLE_ID                  | Number                            |
# response example
```
json {
	code: 0 ,
	message : "",
	trace_pros : [
		{"schema_name":"SYSDPFS", "table_name":"SYSTABLES","create_time":"2026-03-27 00:53:51","key_cols":<主键数量>,"TABLE_ID":0},
		{"schema_name":"SYSDPFS", "table_name":"SYSCOLUMNS","create_time":"2026-03-27 00:53:51","key_cols":<主键数量>,"TABLE_ID":1},
		{"schema_name":"SYSDPFS", "table_name":"SYSUSERS","create_time":"2026-03-27 00:53:51","key_cols":<主键数量>,"TABLE_ID":2}
	]
}
```