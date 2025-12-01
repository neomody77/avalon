# 配置参考

avalon 使用 TOML 格式的配置文件。本文档详细说明所有可用的配置选项。

## 配置结构

```toml
[global]      # 全局设置
[tls]         # TLS/HTTPS 设置
[[servers]]   # 服务器配置 (数组)
```

---

## [global] 全局设置

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `log_level` | string | `"info"` | 日志级别: `trace`, `debug`, `info`, `warn`, `error` |
| `admin_listen` | string | `"localhost:2019"` | Admin API 监听地址 |
| `access_log` | string | - | 访问日志文件路径 |
| `access_log_format` | string | `"common"` | 日志格式: `common`, `json`, `combined` |

### [global.compression] 压缩设置

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 启用响应压缩 |
| `gzip` | bool | `true` | 启用 gzip |
| `brotli` | bool | `true` | 启用 brotli |
| `min_size` | int | `1024` | 最小压缩大小 (字节) |
| `level` | int | `6` | 压缩级别 (gzip: 1-9, brotli: 0-11) |

### [global.cache] 缓存设置

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 启用响应缓存 |
| `default_ttl` | int | `300` | 默认缓存时间 (秒) |
| `max_entry_size` | int | `10485760` | 单条缓存最大大小 (10MB) |
| `max_cache_size` | int | `104857600` | 缓存总大小上限 (100MB) |
| `cacheable_status` | array | `[200, 301, 302, 304, 307, 308]` | 可缓存的状态码 |
| `cacheable_methods` | array | `["GET", "HEAD"]` | 可缓存的请求方法 |

**示例:**

```toml
[global]
log_level = "info"
access_log = "/var/log/avalon/access.log"
access_log_format = "json"

[global.compression]
enabled = true
gzip = true
brotli = true
min_size = 1024
level = 6

[global.cache]
enabled = true
default_ttl = 600
max_cache_size = 209715200  # 200MB
```

---

## [tls] TLS 设置

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `email` | string | - | ACME 账户邮箱 (必填，如果启用 ACME) |
| `acme_enabled` | bool | `true` | 启用 ACME 自动证书 |
| `acme_ca` | string | Let's Encrypt | ACME CA URL |
| `storage_path` | string | `"./certs"` | 证书存储目录 |
| `cert_path` | string | - | 手动指定证书文件路径 |
| `key_path` | string | - | 手动指定私钥文件路径 |

**ACME CA 可选值:**
- `letsencrypt` 或 `https://acme-v02.api.letsencrypt.org/directory` (默认)
- `le-staging` - Let's Encrypt 测试环境
- `zerossl` - ZeroSSL
- `buypass` - Buypass
- `google` - Google Trust Services
- 自定义 URL

**示例:**

```toml
# 使用 Let's Encrypt 自动证书
[tls]
email = "admin@example.com"
acme_enabled = true
storage_path = "/etc/avalon/certs"

# 使用自己的证书
[tls]
acme_enabled = false
cert_path = "/etc/ssl/example.com.crt"
key_path = "/etc/ssl/example.com.key"
```

---

## [[servers]] 服务器配置

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `name` | string | `"default"` | 服务器名称 (用于日志) |
| `listen` | array | - | 监听地址列表 (必填) |
| `https_redirect` | bool | `false` | 自动重定向 HTTP 到 HTTPS |
| `routes` | array | `[]` | 路由规则列表 |

**监听地址格式:**
- `:8080` - 所有接口的 8080 端口
- `127.0.0.1:8080` - 仅本地
- `:443` - HTTPS 端口

**示例:**

```toml
[[servers]]
name = "web-server"
listen = [":80", ":443"]
https_redirect = true
```

---

## [[servers.routes]] 路由配置

### [servers.routes.match] 匹配规则

| 选项 | 类型 | 说明 |
|------|------|------|
| `host` | array | 匹配域名列表 |
| `path` | array | 匹配路径前缀列表 |
| `method` | array | 匹配 HTTP 方法 |
| `header` | object | 匹配请求头 |

**匹配逻辑:**
- 所有条件使用 AND 逻辑
- 路径使用前缀匹配
- 域名精确匹配

**示例:**

```toml
[[servers.routes]]
[servers.routes.match]
host = ["api.example.com", "api2.example.com"]
path = ["/api/v1", "/api/v2"]
method = ["GET", "POST"]

[servers.routes.match.header]
X-Custom-Header = "expected-value"
```

---

## Handler 类型

### reverse_proxy - 反向代理

```toml
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000", "127.0.0.1:3001"]
load_balancing = "round_robin"
timeout = 30
upstream_tls = false
```

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `upstreams` | array | - | 上游服务器地址 (必填) |
| `load_balancing` | string | `"round_robin"` | 负载均衡策略 |
| `timeout` | int | `30` | 连接超时 (秒) |
| `upstream_tls` | bool | `false` | 上游使用 TLS |
| `headers_up` | object | `{}` | 添加到上游请求的 Header |
| `headers_down` | object | `{}` | 添加到下游响应的 Header |
| `lb_try_duration` | int | `0` | 故障转移重试时长 (秒) |
| `lb_try_interval` | int | `250` | 重试间隔 (毫秒) |

**负载均衡策略:**
- `round_robin` - 轮询
- `random` - 随机
- `least_conn` - 最少连接
- `ip_hash` - IP 哈希
- `first` - 始终使用第一个

### 健康检查

```toml
[servers.routes.handle.health_check]
path = "/health"
interval = "10s"
timeout = "5s"
expected_status = 200
```

### 会话亲和性 (Sticky Sessions)

```toml
[servers.routes.handle.session_affinity]
affinity_type = "cookie"    # cookie 或 ip_hash
cookie_name = "srv_id"
cookie_max_age = 3600       # 0 = session cookie
```

### file_server - 静态文件服务

```toml
[servers.routes.handle]
type = "file_server"
root = "/var/www/html"
browse = false
index = ["index.html", "index.htm"]
compress = true
```

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `root` | string | - | 根目录 (必填) |
| `browse` | bool | `false` | 启用目录浏览 |
| `index` | array | `["index.html", "index.htm"]` | 索引文件 |
| `compress` | bool | `true` | 启用压缩 |

### static_response - 静态响应

```toml
[servers.routes.handle]
type = "static_response"
status = 200
body = "Hello, World!"

[servers.routes.handle.headers]
Content-Type = "text/plain"
X-Custom = "value"
```

### redirect - 重定向

```toml
[servers.routes.handle]
type = "redirect"
to = "https://example.com{uri}"
code = 301    # 301, 302, 307, 308
```

### script - Rhai 脚本处理

使用 Rhai 脚本语言编写自定义请求处理逻辑。这是最灵活的处理方式，可以实现复杂的业务逻辑。

```toml
[servers.routes.handle]
type = "script"
script = '''
// 访问请求信息
let path = request.path;
let method = request.method;
let host = request.host;
let client_ip = request.client_ip;

// 检查请求头
let auth = request.headers["authorization"];

// 根据条件返回不同响应
if path == "/health" {
    // JSON 响应
    json_response(#{ status: "ok", version: "1.0" })
} else if path.starts_with("/api/") && auth == () {
    // 返回 401 未授权
    response(401, "Unauthorized", #{
        "Content-Type": "text/plain",
        "WWW-Authenticate": "Bearer"
    })
} else {
    // 返回简单响应
    response(200, "Hello, World!", #{})
}
'''
```

**请求上下文 (request 对象):**

| 属性 | 类型 | 说明 |
|------|------|------|
| `path` | string | 请求路径 |
| `method` | string | HTTP 方法 |
| `host` | string | 请求主机名 |
| `client_ip` | string | 客户端 IP |
| `query` | string | 查询字符串 |
| `headers` | map | 请求头 (键小写) |

**内置函数:**

| 函数 | 说明 | 示例 |
|------|------|------|
| `response(status, body, headers)` | 返回自定义响应 | `response(200, "OK", #{})` |
| `json_response(data)` | 返回 JSON 响应 | `json_response(#{ key: "value" })` |
| `redirect(url)` | 302 重定向 | `redirect("https://example.com")` |
| `redirect_with_code(url, code)` | 指定状态码重定向 | `redirect_with_code("/new", 301)` |
| `url_encode(str)` | URL 编码 | `url_encode("hello world")` |
| `url_decode(str)` | URL 解码 | `url_decode("hello%20world")` |
| `base64_encode(str)` | Base64 编码 | `base64_encode("hello")` |
| `base64_decode(str)` | Base64 解码 | `base64_decode("aGVsbG8=")` |
| `regex_match(pattern, text)` | 正则匹配 | `regex_match("^/api/", path)` |
| `regex_replace(pattern, replacement, text)` | 正则替换 | `regex_replace("old", "new", text)` |
| `json_parse(str)` | 解析 JSON | `json_parse('{"a":1}')` |
| `json_stringify(obj)` | 转为 JSON 字符串 | `json_stringify(#{ a: 1 })` |
| `query_param(name)` | 获取查询参数 | `query_param("page")` |
| `hash_md5(str)` | MD5 哈希 | `hash_md5("password")` |
| `hash_sha256(str)` | SHA256 哈希 | `hash_sha256("data")` |
| `time_now()` | 当前 Unix 时间戳 | `time_now()` |

**示例 - API 网关路由:**

```toml
[servers.routes.handle]
type = "script"
script = '''
let path = request.path;
let api_key = request.headers["x-api-key"];

// 验证 API Key
if api_key != "secret-key-123" {
    response(401, json_stringify(#{ error: "Invalid API key" }), #{
        "Content-Type": "application/json"
    })
} else if path.starts_with("/v1/users") {
    // 转发到用户服务 (返回 proxy 指令)
    #{ proxy: "user-service:8080" }
} else if path.starts_with("/v1/orders") {
    // 转发到订单服务
    #{ proxy: "order-service:8080" }
} else {
    json_response(#{ error: "Not Found", path: path })
}
'''
```

**示例 - A/B 测试:**

```toml
[servers.routes.handle]
type = "script"
script = '''
// 基于客户端 IP 的简单 A/B 测试
let ip_hash = hash_md5(request.client_ip);
let variant = if ip_hash.starts_with("0") || ip_hash.starts_with("1") { "A" } else { "B" };

response(200, "", #{
    "X-AB-Variant": variant,
    "Set-Cookie": `ab_variant=${variant}; Path=/; Max-Age=86400`
})
'''
```

---

## [servers.routes.handle.rewrite] URL 重写

```toml
[servers.routes.handle.rewrite]
strip_path_prefix = "/api"          # 去除路径前缀
add_path_prefix = "/v1"             # 添加路径前缀
replace_path = "/new/path"          # 替换整个路径

[servers.routes.handle.rewrite.path_regex]
pattern = "/old/(.*)"
replacement = "/new/$1"

# 请求头修改
[servers.routes.handle.rewrite.request_headers_set]
X-Forwarded-Proto = "https"

[servers.routes.handle.rewrite.request_headers_add]
X-Request-ID = "generated-id"

# 响应头修改
[servers.routes.handle.rewrite.response_headers_set]
X-Frame-Options = "DENY"
```

---

## [servers.routes.handle.auth] 认证

### Basic 认证

```toml
[servers.routes.handle.auth]
realm = "Protected Area"
exclude_paths = ["/health", "/metrics"]

[[servers.routes.handle.auth.basic]]
username = "admin"
password = "password123"

[[servers.routes.handle.auth.basic]]
username = "user"
password = "$2a$10$..."  # bcrypt hash
```

### API Key 认证

```toml
[[servers.routes.handle.auth.api_keys]]
key = "sk-xxxx"
name = "production"
source = "header"       # header 或 query
param_name = "X-API-Key"

[[servers.routes.handle.auth.api_keys]]
key = "pk-yyyy"
source = "query"
param_name = "api_key"
```

### JWT 认证

```toml
[servers.routes.handle.auth.jwt]
secret = "your-secret-key"
algorithm = "HS256"
header = "Authorization"
issuer = "your-issuer"
audience = "your-audience"
```

---

## [servers.routes.handle.cors] CORS 跨域

配置跨域资源共享 (CORS) 规则：

```toml
[servers.routes.handle.cors]
allowed_origins = ["https://example.com", "https://app.example.com"]
allowed_methods = ["GET", "POST", "PUT", "DELETE"]
allowed_headers = ["Content-Type", "Authorization"]
expose_headers = ["X-Custom-Header"]
allow_credentials = true
max_age = 3600
```

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `allowed_origins` | array | `[]` | 允许的源 (必填)，使用 `["*"]` 允许所有 |
| `allowed_methods` | array | `["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]` | 允许的 HTTP 方法 |
| `allowed_headers` | array | `["Content-Type", "Authorization", "X-Requested-With"]` | 允许的请求头 |
| `expose_headers` | array | `[]` | 暴露给客户端的响应头 |
| `allow_credentials` | bool | `false` | 是否允许携带凭证 |
| `max_age` | int | `86400` | 预检请求缓存时间 (秒) |

**最简配置 (允许所有源):**

```toml
[servers.routes.handle.cors]
allowed_origins = ["*"]
```

**注意:**
- 使用 `*` 通配符时，如果 `allow_credentials = true`，会自动回显请求的 Origin
- 预检请求 (OPTIONS) 会自动处理并返回 CORS 响应头

---

## 故障转移与重试

配置上游服务器故障转移行为：

```toml
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"]
lb_try_duration = 5       # 重试总时长 (秒)
lb_try_interval = 250     # 重试间隔 (毫秒)
```

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `lb_try_duration` | int | `0` | 重试总时长 (秒)，0 表示不重试 |
| `lb_try_interval` | int | `250` | 两次重试之间的间隔 (毫秒) |

**工作机制:**
- 当连接上游失败时，在 `lb_try_duration` 时间内尝试其他上游
- 每次重试之间等待 `lb_try_interval` 毫秒
- 适用于连接失败、连接超时等场景
- 配合健康检查使用效果更佳

---

## 完整配置示例

```toml
# 全局配置
[global]
log_level = "info"
access_log = "/var/log/avalon/access.log"
access_log_format = "json"

[global.compression]
enabled = true
level = 6

[global.cache]
enabled = true
default_ttl = 300

# TLS 配置
[tls]
email = "admin@example.com"
acme_enabled = true
storage_path = "/etc/avalon/certs"

# HTTP 重定向服务器
[[servers]]
name = "http-redirect"
listen = [":80"]
https_redirect = true

# HTTPS 主服务器
[[servers]]
name = "main"
listen = [":443"]

# API 路由
[[servers.routes]]
[servers.routes.match]
host = ["api.example.com"]
path = ["/api"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000", "127.0.0.1:3001"]
load_balancing = "round_robin"
timeout = 30

[servers.routes.handle.health_check]
path = "/health"
interval = "10s"

[servers.routes.handle.rewrite]
strip_path_prefix = "/api"

[servers.routes.handle.auth]
realm = "API"

[[servers.routes.handle.auth.api_keys]]
key = "sk-production-key"
source = "header"
param_name = "Authorization"

# 静态文件路由
[[servers.routes]]
[servers.routes.match]
host = ["www.example.com"]

[servers.routes.handle]
type = "file_server"
root = "/var/www/html"
index = ["index.html"]

# 默认路由 (404)
[[servers.routes]]
[servers.routes.handle]
type = "static_response"
status = 404
body = "Not Found"
```
