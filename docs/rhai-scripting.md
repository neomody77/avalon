# Rhai 脚本重写

avalon 支持使用 [Rhai](https://rhai.rs/) 脚本语言进行高级 URL 重写和请求转换。Rhai 是一个专为嵌入 Rust 应用设计的脚本语言，语法类似 JavaScript。

## 两种模式

### 1. 表达式模式 (声明式)

使用独立的表达式字段，适合简单场景：

```toml
[[servers.routes.handle.rewrite.rhai_rules]]
when = 'request.path.starts_with("/api/v1")'
path = '"/v2" + request.path.sub_string(7)'
headers_set = { "X-API-Version" = '"v2"' }
```

### 2. 脚本模式 (命令式)

使用完整的 Rhai 脚本，适合复杂逻辑：

```toml
[[servers.routes.handle.rewrite.rhai_rules]]
script = '''
    if request.path.starts_with("/api/v1") {
        request.path = "/v2" + request.path.sub_string(7);
        request.headers["X-API-Version"] = "v2";
    }

    if request.headers["X-Debug"] == "true" {
        request.headers["X-Original-Path"] = request.path;
    }
'''
```

---

## request 对象

在 Rhai 脚本中，可以访问以下请求属性：

| 属性 | 类型 | 说明 | 可修改 |
|------|------|------|--------|
| `request.method` | string | HTTP 方法 (GET, POST 等) | 否 |
| `request.path` | string | 请求路径 | 是 |
| `request.query` | string | 查询字符串 | 是 |
| `request.host` | string | 请求域名 | 否 |
| `request.client_ip` | string | 客户端 IP | 否 |
| `request.headers` | map | 请求头 (key-value) | 是 |
| `request.params` | map | 解析后的查询参数 | 否 |

---

## 内置函数

### 字符串操作

```rhai
// 判断
"hello".contains("ell")       // true
"hello".starts_with("he")     // true
"hello".ends_with("lo")       // true

// 转换
"Hello".to_lower()            // "hello"
"hello".to_upper()            // "HELLO"
"  hello  ".trim()            // "hello"

// 替换
"hello".replace("l", "L")     // "heLLo"

// 分割
"a,b,c".split(",")            // ["a", "b", "c"]

// 截取
"hello".sub_string(1, 3)      // "ell"
```

### 正则表达式

```rhai
// 匹配
matches("/api/v1/users", "/api/v\\d+/.*")    // true

// 替换
regex_replace("/user/123/profile", "/user/(\\d+)", "/users/$1")
// 结果: "/users/123/profile"
```

### URL 编码

```rhai
url_encode("hello world")     // "hello%20world"
url_decode("hello%20world")   // "hello world"
```

### Base64

```rhai
base64_encode("hello")        // "aGVsbG8="
base64_decode("aGVsbG8=")     // "hello"
```

### 哈希

```rhai
hash("hello", "sha256")       // "2cf24dba5fb0a30e..."
hash("hello", "md5")          // "5d41402abc4b2a76..."
```

### 工具函数

```rhai
uuid()                        // 生成 UUID v4
now()                         // 当前 Unix 时间戳
coalesce(a, b, c)            // 返回第一个非空值
default(value, "fallback")   // 如果 value 为空返回 fallback
```

---

## 使用示例

### 1. API 版本路由

根据请求头路由到不同版本：

```toml
[[servers.routes.handle.rewrite.rhai_rules]]
script = '''
    let version = request.headers["X-API-Version"];

    if version == "v2" {
        request.path = "/v2" + request.path;
    } else if version == "v3" {
        request.path = "/v3" + request.path;
    } else {
        request.path = "/v1" + request.path;
    }
'''
```

### 2. 用户 ID 哈希路由

根据用户 ID 路由到不同分片：

```toml
[[servers.routes.handle.rewrite.rhai_rules]]
script = '''
    let user_id = request.params["user_id"];

    if user_id != () {
        let shard = hash(user_id, "md5").sub_string(0, 2);
        request.headers["X-Shard"] = shard;
    }
'''
```

### 3. 请求签名验证

```toml
[[servers.routes.handle.rewrite.rhai_rules]]
when = 'request.headers["X-Signature"] == ()'
action = "reject"
reject_status = 401
reject_body = "Missing signature"

[[servers.routes.handle.rewrite.rhai_rules]]
script = '''
    let sig = request.headers["X-Signature"];
    let expected = hash(request.path + request.query, "sha256").sub_string(0, 16);

    if sig != expected {
        // 签名无效，设置标记让后续规则处理
        request.headers["X-Signature-Valid"] = "false";
    } else {
        request.headers["X-Signature-Valid"] = "true";
    }
'''
```

### 4. A/B 测试分流

```toml
[[servers.routes.handle.rewrite.rhai_rules]]
script = '''
    let user_id = request.headers["X-User-ID"];

    if user_id != () {
        // 基于用户 ID 哈希分流
        let hash_val = hash(user_id, "md5");
        let bucket = parse_int(hash_val.sub_string(0, 2), 16) % 100;

        if bucket < 10 {
            // 10% 流量到新版本
            request.headers["X-Experiment"] = "new";
            request.path = "/experiment" + request.path;
        } else {
            request.headers["X-Experiment"] = "control";
        }
    }
'''
```

### 5. 查询参数转路径

将 `/search?q=hello` 转换为 `/search/hello`：

```toml
[[servers.routes.handle.rewrite.rhai_rules]]
when = 'request.path == "/search" && request.params["q"] != ()'
script = '''
    let query = request.params["q"];
    request.path = "/search/" + url_encode(query);
    request.query = "";
'''
```

### 6. 地理位置路由

根据客户端 IP 添加地区标识：

```toml
[[servers.routes.handle.rewrite.rhai_rules]]
script = '''
    let ip = request.client_ip;

    // 简单示例：根据 IP 前缀判断
    if ip.starts_with("10.") {
        request.headers["X-Region"] = "internal";
    } else if ip.starts_with("192.168.") {
        request.headers["X-Region"] = "local";
    } else {
        request.headers["X-Region"] = "external";
    }
'''
```

### 7. 条件重定向

```toml
[[servers.routes.handle.rewrite.rhai_rules]]
when = 'request.path == "/old-page"'
action = "redirect"
redirect_status = 301
redirect_location = '"/new-page"'

[[servers.routes.handle.rewrite.rhai_rules]]
when = 'request.host == "old.example.com"'
action = "redirect"
redirect_status = 301
redirect_location = '"https://new.example.com" + request.path'
```

### 8. 请求拒绝

```toml
# 拒绝特定 User-Agent
[[servers.routes.handle.rewrite.rhai_rules]]
when = 'request.headers["User-Agent"].contains("BadBot")'
action = "reject"
reject_status = 403
reject_body = "Access Denied"

# 拒绝没有认证的请求
[[servers.routes.handle.rewrite.rhai_rules]]
when = 'request.headers["Authorization"] == () && !request.path.starts_with("/public")'
action = "reject"
reject_status = 401
reject_body = "Unauthorized"
```

---

## 规则执行顺序

1. 规则按配置顺序依次执行
2. 每条规则先检查 `when` 条件
3. 条件满足时执行脚本或表达式
4. 如果 `stop = true` (默认)，匹配后停止处理后续规则
5. 如果 `stop = false`，继续处理后续规则

```toml
# 规则 1: 添加通用 header (继续执行后续规则)
[[servers.routes.handle.rewrite.rhai_rules]]
headers_set = { "X-Processed" = '"true"' }
stop = false

# 规则 2: 版本路由
[[servers.routes.handle.rewrite.rhai_rules]]
when = 'request.headers["X-Version"] == "v2"'
path = '"/v2" + request.path'
# stop = true (默认)

# 规则 3: 默认版本
[[servers.routes.handle.rewrite.rhai_rules]]
path = '"/v1" + request.path'
```

---

## 调试技巧

使用 Header 来调试脚本：

```toml
[[servers.routes.handle.rewrite.rhai_rules]]
script = '''
    // 添加调试信息到响应头
    request.headers["X-Debug-Path"] = request.path;
    request.headers["X-Debug-Query"] = request.query;
    request.headers["X-Debug-Time"] = "" + now();

    // 你的实际逻辑
    if request.path.starts_with("/api") {
        request.path = "/v1" + request.path;
        request.headers["X-Debug-Rewritten"] = "true";
    }
'''
```

---

## 性能注意事项

1. Rhai 脚本在启动时编译，运行时性能良好
2. 避免在脚本中做复杂计算或循环
3. 简单条件判断优先使用 `when` 表达式
4. 频繁访问的路由考虑使用静态重写规则
