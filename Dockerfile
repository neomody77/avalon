# Build stage
FROM rust:1.82-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    g++ \
    perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/caddy-rs /usr/local/bin/caddy-rs

# Create directories for certs and config
RUN mkdir -p /app/certs /var/log

# Default config location
VOLUME ["/app/certs", "/app/config"]

# Expose ports
EXPOSE 80 443

# Set entrypoint
ENTRYPOINT ["caddy-rs"]
CMD ["--config", "/app/config/caddy.toml"]
