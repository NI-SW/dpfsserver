
## 溯源数据管理系统API文档

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
parameter                 | type                               | describe
------------------------- | ---------------------------------- | ----------------------------------
user_token                | Number                             | 
schema                    | String                             | 
product_name              | String                             | 
product_number            | Number                             | 
ingredients               | List of (String, String) pairs     | 
base_info                 | List of (String, String) pairs     | 
risk_report               | Number                             | 指定是否生成评估报告, 0 or 1
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
POST
```
# Request
parameter                 | type                               | describe  
------------------------- | ---------------------------------- | ----------------------------------
user_token                | Number                             | 
begin                     | Number                             | 提取的起始位置
limit                     | Number                             | 提取的数量
# Response
parameter                 | type                               | describe
------------------------- | ---------------------------------- | ----------------------------------              
code                      | Number                             | 
message                   | String                             | 
total                     | Number                             | 溯源结构总数(全部的数量，不是本次提取的数量)
trace_pros                | Array of Objects                   | 溯源结构列表
# example
```
{
  code: 0 ,
  message : "",
  total: 128,
  trace_pros : [
    {"group_name":"北京林业大学",product_name:"苹果派","trace_code_prefix":"00000000000000001D05000000000000"},
    {"group_name":"北京林业大学",product_name:"香蕉派","trace_code_prefix":"00000000000000001D09000000000000"},
    {"group_name":"北京林业大学",product_name:"草莓派","trace_code_prefix":"00000000000000001D01000000000000"}
  ]
}
```

# 描述
```
根据溯源码执行溯源操作
```
# URL
```
/api/trace_back
```
# METHOD
```
POST
```
# Request
parameter                 | type                              | describe
------------------------- | ----------------------------------| ----------------------------------
user_token                | Number                            |
trace_code                | String (40 Bytes)                 |
trace_detail              | Number                            | 0 or 1, 是否返回详细交易信息
ingre_detail              | Number                            | 0 or 1, 是否返回详细配料信息
ai_risk                   | Number                            | 0 or 1, 是否返回AI风险评估信息
# Response
parameter                 | type
------------------------- | ----------------------------------
code                      | Number
message                   | String
trace_result              | String
ai_risk_report            | String
# example request
```
{
  "user_token": 0,
  "trace_code": "00000000000000001D050000000000000F000000",
  "trace_detail": 1,
  "ingre_detail": 0,
  "ai_risk": 1
}
```
# example response
```
{"code":200,"message":"","trace_result":"
Base Info: {
cstate/校验状态: 1
ctime/上一次校验时间: 2026-03-30 10:51:34
uid/产品编号: 15
质量检测报告: https://mbd.baidu.com/newspage/data/dtlandingsuper?nid=dt_5393403645428020230&sourceFrom=search_a
生产日期: 2026-01-01
ccount/校验次数: 9
名称: 富庄阁烤鸭酱料
保质期: 1年
}
Trade Info: {
}
Ingredient Info: {
Ingredient Percentage: 7.00
Ingredient Name: 橄榄油
child ingredient trace result: {
Ingredient Base Info:
 过氧化值: 8.3
 质量报告: https://www.cqn.com.cn/ms/content/2019-01/04/content_6643996.htm
 种类: 特级初榨
 生产日期: 2026-03-01
 名称: 嘉禾特级初榨橄榄油
 Ingredient Info:
 Ingredient Percentage: 74.00
 Ingredient Name: 单不饱和脂肪酸
}
-----------------
Ingredient Percentage: 90.00
Ingredient Name: 纯净水
child ingredient trace result: {
}
-----------------
Ingredient Percentage: 3.00
Ingredient Name: 食用盐
child ingredient trace result: {
Ingredient Base Info:
 生产日期: 2026-3-29
 安全检测报告: http://www.yn.xinhuanet.com/20251209/138bdcccac144b17a3b86e84edb430d9/c.html
 品牌: 海天食用盐
 净含量: 500g
 保质期: 3年
 Ingredient Info:
 Ingredient Percentage: 100.00
 Ingredient Name: 氯化钠
}
-----------------
}
","ai_risk_report":"
**总体风险评估：低**  
理由：产品校验状态正常（在有效期内），校验记录完整（校验次数9次），主要成分（水、橄榄油、食用盐）均有溯源信息，且原料生产日期与产品保质期匹配。

**成分链风险分析：**  
1. **橄榄油（7%）**：原料“嘉禾特级初榨橄榄油”过氧化值8.3（需对照国标判断是否超标），特级初榨橄榄油易氧化，需关注储存条件。  
2. **纯净水（90%）**：无子成分溯源信息，但作为常见原料风险较低。  
3. **食用盐（3%）**：原料“海天食用盐”有安全检测报告，氯化钠纯度100%，风险可控。

**潜在风险点：**  
1. **橄榄油氧化风险**：过氧化值数据需核对其是否符合≤10mmol/kg的国标要求，若接近上限可能存在油脂酸败隐患。  
2. **纯净水溯源缺失**：未提供具体水源检测报告，存在微生物或污染物潜在风险。  
3. **生产时间差**：橄榄油生产日期（2026-03-01）晚于酱料生产日期（2026-01-01），逻辑矛盾，可能影响原料新鲜度评估。  
4. **链接报告时效性**：部分检测报告链接时间较早（如2019年），可能不反映当前批次质量。"
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
POST
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

# 描述
```
执行交易操作
```
# URL
```
/api/make_trade
```
# METHOD
```
POST
```
# Request
parameter                 | type                              | describe
------------------------- | ----------------------------------| ----------------------------------
user_token                | Number                            |
trade_schema              | String                            | 发生交易的溯源组
trade_product_name        | String                            | 发生交易的产品名称
trade_product_start_id    | Number                            | 发生交易的产品起始ID
trade_product_number      | Number                            | 发生交易的产品数量
buyer                     | String                            | 买方名称
buyer_addr                | String                            | 买方地址
buyer_phone               | String                            | 买方联系方式
seller                    | String                            | 卖方名称
seller_addr               | String                            | 卖方地址
seller_phone              | String                            | 卖方联系方式
logistics_info            | String                            | 物流信息
other_info                | String                            | 其它信息（备注）
trade_price               | String                            | 发生金额
# Response
parameter                 | type
------------------------- | ----------------------------------
code                      | Number
message                   | String