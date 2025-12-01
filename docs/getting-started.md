# avalon 快速入门

avalon 是一个用 Rust 编写的高性能反向代理服务器，基于 Cloudflare 的 Pingora 框架。它提供自动 HTTPS、负载均衡、URL 重写等功能。

## 安装

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/your-repo/avalon.git
cd avalon

# 编译 release 版本
cargo build --release

# 可执行文件在 target/release/avalon
```

### 使用 Docker

```bash
docker build -t avalon .
docker run -p 80:80 -p 443:443 -v ./caddy.toml:/app/caddy.toml avalon
```

## 最小配置

创建 `caddy.toml` 配置文件：

```toml
# 全局设置
[global]
log_level = "info"

# TLS 设置 (可选)
[tls]
acme_enabled = false

# 服务器配置
[[servers]]
name = "web"
listen = [":8080"]

# 路由规则
[[servers.routes]]
[servers.routes.match]
path = ["/"]

[servers.routes.handle]
type = "static_response"
status = 200
body = "Hello, avalon!"

[servers.routes.handle.headers]
Content-Type = "text/plain"
```

## 运行

```bash
./target/release/avalon --config caddy.toml
```

访问 http://localhost:8080 即可看到响应。

## 常用场景

### 1. 反向代理

将请求转发到后端服务：

```toml
[[servers]]
name = "api-proxy"
listen = [":8080"]

[[servers.routes]]
[servers.routes.match]
path = ["/api"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]
```

### 2. 多后端负载均衡

```toml
[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"]
load_balancing = "round_robin"  # 可选: random, least_conn, ip_hash
```

### 3. 静态文件服务

```toml
[[servers.routes]]
[servers.routes.match]
path = ["/static"]

[servers.routes.handle]
type = "file_server"
root = "/var/www/static"
browse = false
index = ["index.html"]
```

### 4. 自动 HTTPS (Let's Encrypt)

```toml
[tls]
email = "admin@example.com"
acme_enabled = true
storage_path = "./certs"

[[servers]]
name = "https-server"
listen = [":443"]

[[servers.routes]]
[servers.routes.match]
host = ["example.com"]
path = ["/"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]
```

### 5. HTTP 重定向到 HTTPS

```toml
[[servers]]
name = "http-redirect"
listen = [":80"]
https_redirect = true
```

## 配置热重载

avalon 支持配置热重载。修改配置文件后，发送 SIGHUP 信号：

```bash
kill -HUP $(pidof avalon)
```

## 下一步

- [配置参考](./configuration.md) - 完整的配置选项说明
- [常用示例](./examples.md) - 更多配置示例
- [Rhai 脚本](./rhai-scripting.md) - 高级 URL 重写功能
