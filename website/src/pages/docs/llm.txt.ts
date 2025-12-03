import type { APIRoute } from 'astro';

const content = `# Avalon - High-Performance Reverse Proxy

Avalon is a reverse proxy server built with Rust and Cloudflare Pingora framework.

## Installation

\`\`\`bash
git clone https://github.com/neomody77/avalon.git
cd avalon
cargo build --release
# Binary at target/release/avalon
\`\`\`

## Run

\`\`\`bash
avalon --config avalon.toml
\`\`\`

## Configuration (TOML format)

### Minimal Example

\`\`\`toml
[global]
log_level = "info"

[tls]
acme_enabled = false

[[servers]]
name = "web"
listen = [":8080"]

[[servers.routes]]
[servers.routes.match]
path = ["/"]

[servers.routes.handle]
type = "static_response"
status = 200
body = "Hello, Avalon!"
\`\`\`

### Reverse Proxy

\`\`\`toml
[[servers]]
name = "api"
listen = [":8080"]

[[servers.routes]]
[servers.routes.match]
path = ["/api"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]
\`\`\`

### Load Balancing

\`\`\`toml
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"]
load_balancing = "round_robin"  # Options: round_robin, random, least_conn, ip_hash, first
\`\`\`

### Static File Server

\`\`\`toml
[servers.routes.handle]
type = "file_server"
root = "/var/www/html"
index = ["index.html"]
browse = false
compress = true
\`\`\`

### Auto HTTPS (Let's Encrypt)

\`\`\`toml
[tls]
email = "admin@example.com"
acme_enabled = true
acme_ca = "letsencrypt"  # Options: letsencrypt, le-staging, zerossl, buypass, google
storage_path = "./certs"

[[servers]]
listen = [":443"]

[[servers.routes]]
[servers.routes.match]
host = ["example.com"]
\`\`\`

### HTTP to HTTPS Redirect

\`\`\`toml
[[servers]]
name = "http-redirect"
listen = [":80"]
https_redirect = true
\`\`\`

### Health Check

\`\`\`toml
[servers.routes.handle.health_check]
path = "/health"
interval = "10s"
timeout = "5s"
expected_status = 200
\`\`\`

### Authentication

Basic Auth:
\`\`\`toml
[servers.routes.handle.auth]
realm = "Protected"

[[servers.routes.handle.auth.basic]]
username = "admin"
password = "password123"
\`\`\`

API Key:
\`\`\`toml
[[servers.routes.handle.auth.api_keys]]
key = "sk-xxxx"
source = "header"
param_name = "X-API-Key"
\`\`\`

JWT:
\`\`\`toml
[servers.routes.handle.auth.jwt]
secret = "your-secret-key"
algorithm = "HS256"
header = "Authorization"
\`\`\`

### CORS

\`\`\`toml
[servers.routes.handle.cors]
allowed_origins = ["https://example.com"]
allowed_methods = ["GET", "POST", "PUT", "DELETE"]
allowed_headers = ["Content-Type", "Authorization"]
allow_credentials = true
max_age = 3600
\`\`\`

### Rate Limiting

\`\`\`toml
[servers.routes.handle.rate_limit]
requests_per_second = 100
burst = 50
\`\`\`

### Compression

\`\`\`toml
[global.compression]
enabled = true
gzip = true
brotli = true
min_size = 1024
level = 6
\`\`\`

### Caching

\`\`\`toml
[global.cache]
enabled = true
default_ttl = 300
max_entry_size = 10485760
max_cache_size = 104857600
\`\`\`

## Rhai Scripting

Avalon supports Rhai scripts for advanced request handling.

### Script Handler

\`\`\`toml
[servers.routes.handle]
type = "script"
script = '''
let path = request.path;
let method = request.method;

if path == "/health" {
    json_response(#{
        status: "ok",
        timestamp: time_now()
    })
} else {
    #{ proxy: "backend:8080" }
}
'''
\`\`\`

### Request Object Properties

- request.path - Request path (string)
- request.method - HTTP method (string)
- request.host - Hostname (string)
- request.client_ip - Client IP (string)
- request.query - Query string (string)
- request.headers - Headers map (lowercase keys)

### Built-in Functions

Response:
- response(status, body, headers) - Custom response
- json_response(data) - JSON response with Content-Type
- redirect(url) - 302 redirect
- redirect_with_code(url, code) - Redirect with status code

String:
- url_encode(str) / url_decode(str)
- base64_encode(str) / base64_decode(str)
- regex_match(pattern, text)
- regex_replace(pattern, replacement, text)

JSON:
- json_parse(str)
- json_stringify(obj)

Utility:
- query_param(name) - Get query parameter
- hash_md5(str) / hash_sha256(str)
- time_now() - Unix timestamp

### Script Examples

API Gateway:
\`\`\`rhai
let api_key = request.headers["x-api-key"];
if api_key != "secret" {
    response(401, "Unauthorized", #{})
} else if request.path.starts_with("/v1/users") {
    #{ proxy: "user-service:8080" }
} else {
    #{ proxy: "default-service:8080" }
}
\`\`\`

## Hot Reload

Send SIGHUP to reload configuration without downtime:

\`\`\`bash
kill -HUP $(pidof avalon)
\`\`\`

## Handler Types Summary

| Type | Description |
|------|-------------|
| reverse_proxy | Proxy to upstream servers |
| file_server | Serve static files |
| static_response | Return fixed response |
| redirect | HTTP redirect |
| script | Rhai script handler |

## Global Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| log_level | string | "info" | trace/debug/info/warn/error |
| admin_listen | string | "localhost:2019" | Admin API address |
| access_log | string | - | Access log file path |
| access_log_format | string | "common" | common/json/combined |

## TLS Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| email | string | - | ACME account email |
| acme_enabled | bool | true | Enable ACME |
| acme_ca | string | letsencrypt | CA provider |
| storage_path | string | "./certs" | Cert storage |
| cert_path | string | - | Manual cert path |
| key_path | string | - | Manual key path |
`;

export const GET: APIRoute = () => {
  return new Response(content, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
    },
  });
};
