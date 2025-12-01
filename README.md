# Avalon

A high-performance, production-ready reverse proxy server written in Rust, powered by Cloudflare's [Pingora](https://github.com/cloudflare/pingora) framework.

## Features

### Core Proxy
- **Reverse Proxy** - Route requests to upstream servers
- **Load Balancing** - Round-robin, random, least connections, IP hash
- **HTTP/2 Support** - Full HTTP/2 support for upstream connections
- **mTLS** - Mutual TLS authentication for upstream connections
- **Connection Pooling** - Efficient connection reuse with keepalive
- **Request Timeouts** - Configurable connect, read, write, and total timeouts
- **Retry Mechanism** - Automatic retry on upstream failures
- **Request Body Limits** - Configurable maximum request body size

### Reliability
- **Health Checks** - Active health monitoring of upstream servers
- **Circuit Breaker** - Prevent cascading failures with automatic failover
- **Graceful Shutdown** - Drain connections before shutdown

### Security
- **Automatic HTTPS** - Let's Encrypt, ZeroSSL, Google Trust Services, Buypass
- **IP Filtering** - Whitelist/blacklist with CIDR support
- **Rate Limiting** - Token bucket algorithm per client IP
- **Authentication** - Basic Auth, API Key, JWT
- **CORS** - Cross-Origin Resource Sharing support

### Performance
- **Response Caching** - In-memory LRU cache with TTL
- **Compression** - Gzip and Brotli compression
- **Static File Server** - Efficient static file serving

### Observability
- **Access Logs** - Common, Combined, and JSON formats
- **Prometheus Metrics** - Request counts, latencies, upstream health
- **Request ID** - Unique request tracking

### Configuration
- **Hot Reload** - Update configuration without restart
- **URL Rewriting** - Path manipulation and header modification
- **Rhai Scripting** - Dynamic request handling with scripts

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/example/avalon.git
cd avalon

# Build release version
cargo build --release

# Binary is at target/release/avalon
```

### Docker

```bash
docker build -t avalon .
docker run -p 80:80 -p 443:443 -v ./config.toml:/app/config.toml avalon
```

### Minimal Configuration

Create `config.toml`:

```toml
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
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]
```

### Run

```bash
./target/release/avalon --config config.toml
```

## Configuration Examples

### Reverse Proxy with Load Balancing

```toml
[[servers]]
name = "api"
listen = [":8080"]

[[servers.routes]]
[servers.routes.match]
path = ["/api"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"]
load_balancing = "round_robin"

[servers.routes.handle.health_check]
path = "/health"
interval = "10s"
timeout = "5s"
```

### Automatic HTTPS

```toml
[tls]
email = "admin@example.com"
acme_enabled = true
acme_ca = "letsencrypt"
storage_path = "./certs"

[[servers]]
name = "https"
listen = [":443"]

[[servers.routes]]
[servers.routes.match]
host = ["example.com"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]
```

### Rate Limiting

```toml
[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:3000"]

[servers.routes.handle.rate_limit]
requests_per_second = 100
burst = 20
```

### Authentication

```toml
[[servers.routes]]
[servers.routes.handle.auth]
realm = "Protected API"

[[servers.routes.handle.auth.basic]]
username = "admin"
password = "secret"

# Or use API keys
[[servers.routes.handle.auth.api_keys]]
key = "sk-xxx"
source = "header"
param_name = "X-API-Key"
```

## Architecture

```
avalon/
├── crates/
│   ├── config/     # Configuration parsing and validation
│   ├── proxy/      # Core proxy implementation
│   ├── tls/        # TLS/ACME certificate management
│   └── plugin/     # Plugin system
├── docs/           # Documentation
└── src/            # Main entry point
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [Configuration Reference](docs/configuration.md)
- [Rhai Scripting](docs/rhai-scripting.md)
- [Examples](docs/examples.md)

## Performance

Built on Pingora, Avalon inherits its exceptional performance characteristics:
- Async I/O with Tokio runtime
- Zero-copy request forwarding where possible
- Efficient memory management
- Connection pooling and keepalive

## License

MIT License
