# 常用配置示例

本文档提供常见使用场景的完整配置示例。

---

## 1. 简单反向代理

将所有请求转发到后端服务：

```toml
[global]
log_level = "info"

[tls]
acme_enabled = false

[[servers]]
name = "proxy"
listen = [":8080"]

[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]
```

---

## 2. 多域名虚拟主机

不同域名指向不同后端：

```toml
[global]
log_level = "info"

[tls]
email = "admin@example.com"
acme_enabled = true

[[servers]]
name = "multi-host"
listen = [":443"]

# API 服务
[[servers.routes]]
[servers.routes.match]
host = ["api.example.com"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]

# 博客服务
[[servers.routes]]
[servers.routes.match]
host = ["blog.example.com"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:4000"]

# 静态网站
[[servers.routes]]
[servers.routes.match]
host = ["www.example.com"]

[servers.routes.handle]
type = "file_server"
root = "/var/www/html"
```

---

## 3. 负载均衡集群

多后端负载均衡 + 健康检查：

```toml
[[servers]]
name = "cluster"
listen = [":8080"]

[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = [
    "10.0.0.1:8080",
    "10.0.0.2:8080",
    "10.0.0.3:8080"
]
load_balancing = "least_conn"
timeout = 30

[servers.routes.handle.health_check]
path = "/health"
interval = "10s"
timeout = "3s"
expected_status = 200
```

---

## 4. API 网关

路径分发 + 认证 + 速率限制：

```toml
[[servers]]
name = "api-gateway"
listen = [":443"]

# 用户服务 /api/users/*
[[servers.routes]]
[servers.routes.match]
path = ["/api/users"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["user-service:8080"]

[servers.routes.handle.rewrite]
strip_path_prefix = "/api/users"

[servers.routes.handle.auth]
[[servers.routes.handle.auth.api_keys]]
key = "sk-prod-xxx"
source = "header"
param_name = "Authorization"

# 订单服务 /api/orders/*
[[servers.routes]]
[servers.routes.match]
path = ["/api/orders"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["order-service:8080"]

[servers.routes.handle.rewrite]
strip_path_prefix = "/api/orders"

# 公开接口 (无认证)
[[servers.routes]]
[servers.routes.match]
path = ["/api/public"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["public-service:8080"]
```

---

## 5. 静态网站 + API

前后端分离部署：

```toml
[[servers]]
name = "webapp"
listen = [":443"]

# API 请求转发到后端
[[servers.routes]]
[servers.routes.match]
path = ["/api"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]

# WebSocket 连接
[[servers.routes]]
[servers.routes.match]
path = ["/ws"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]

# 静态文件
[[servers.routes]]
[servers.routes.handle]
type = "file_server"
root = "/var/www/dist"
index = ["index.html"]

# SPA fallback - 所有 404 返回 index.html
# (需要在前端路由处理)
```

---

## 6. HTTPS 强制跳转

HTTP 自动跳转到 HTTPS：

```toml
[tls]
email = "admin@example.com"
acme_enabled = true

# HTTP 服务器 - 仅做跳转
[[servers]]
name = "http-redirect"
listen = [":80"]
https_redirect = true

# HTTPS 服务器 - 实际服务
[[servers]]
name = "https-main"
listen = [":443"]

[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]
```

---

## 7. 上游 TLS (HTTPS 后端)

代理到 HTTPS 后端服务：

```toml
[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["backend.internal:443"]
upstream_tls = true
timeout = 60
```

---

## 8. 添加/修改请求头

代理时修改 Header：

```toml
[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]

# 添加到上游请求
[servers.routes.handle.headers_up]
X-Forwarded-Proto = "https"
X-Real-IP = "client_ip"

# 添加到下游响应
[servers.routes.handle.headers_down]
X-Powered-By = "avalon"
Strict-Transport-Security = "max-age=31536000"
```

---

## 9. 会话保持 (Sticky Sessions)

用户请求始终路由到同一后端：

```toml
[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["10.0.0.1:8080", "10.0.0.2:8080"]
load_balancing = "round_robin"

[servers.routes.handle.session_affinity]
affinity_type = "cookie"
cookie_name = "SERVERID"
cookie_max_age = 3600
```

---

## 10. URL 重写

路径重写与正则替换：

```toml
[[servers.routes]]
[servers.routes.match]
path = ["/old-api"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]

[servers.routes.handle.rewrite]
# /old-api/users -> /v2/users
strip_path_prefix = "/old-api"
add_path_prefix = "/v2"

# 正则替换
[servers.routes.handle.rewrite.path_regex]
pattern = "/user/(\\d+)/profile"
replacement = "/users/$1"
```

---

## 11. Basic 认证保护

保护管理后台：

```toml
[[servers.routes]]
[servers.routes.match]
path = ["/admin"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]

[servers.routes.handle.auth]
realm = "Admin Area"
exclude_paths = ["/admin/health"]

[[servers.routes.handle.auth.basic]]
username = "admin"
password = "secure-password"
```

---

## 12. CORS 跨域配置

### 允许所有源 (开发环境)

```toml
[[servers.routes]]
[servers.routes.match]
path = ["/api"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]

[servers.routes.handle.cors]
allowed_origins = ["*"]
```

### 指定源 (生产环境)

```toml
[[servers.routes]]
[servers.routes.match]
path = ["/api"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]

[servers.routes.handle.cors]
allowed_origins = ["https://example.com", "https://app.example.com"]
allowed_methods = ["GET", "POST", "PUT", "DELETE"]
allowed_headers = ["Content-Type", "Authorization", "X-Requested-With"]
allow_credentials = true
max_age = 86400
```

---

## 13. 故障转移配置

多后端自动故障转移：

```toml
[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"]
load_balancing = "round_robin"
lb_try_duration = 10    # 10秒内持续重试
lb_try_interval = 500   # 每500ms重试一次

[servers.routes.handle.health_check]
path = "/health"
interval = "5s"
timeout = "2s"
```

---

## 14. 完整生产配置

```toml
[global]
log_level = "info"
access_log = "/var/log/avalon/access.log"
access_log_format = "json"

[global.compression]
enabled = true
gzip = true
brotli = true
level = 6

[global.cache]
enabled = true
default_ttl = 300

[tls]
email = "admin@example.com"
acme_enabled = true
storage_path = "/etc/avalon/certs"

# HTTP 跳转
[[servers]]
name = "http"
listen = [":80"]
https_redirect = true

# HTTPS 主服务
[[servers]]
name = "https"
listen = [":443"]

# API
[[servers.routes]]
[servers.routes.match]
host = ["api.example.com"]
path = ["/"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["10.0.1.1:8080", "10.0.1.2:8080", "10.0.1.3:8080"]
load_balancing = "least_conn"
timeout = 30

[servers.routes.handle.health_check]
path = "/health"
interval = "10s"

[servers.routes.handle.auth]
[[servers.routes.handle.auth.api_keys]]
key = "sk-production-key"
source = "header"
param_name = "Authorization"

# 静态网站
[[servers.routes]]
[servers.routes.match]
host = ["www.example.com"]

[servers.routes.handle]
type = "file_server"
root = "/var/www/html"
compress = true

# 默认 404
[[servers.routes]]
[servers.routes.handle]
type = "static_response"
status = 404
body = "Not Found"

[servers.routes.handle.headers]
Content-Type = "text/plain"
```
