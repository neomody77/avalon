//! caddy-rs: A Caddy-like web server written in Rust
//!
//! Built on Cloudflare's Pingora framework for high-performance
//! reverse proxying with automatic HTTPS via Let's Encrypt.

use anyhow::{Context, Result};
use caddy_core::{Config, HandlerConfig};
use caddy_proxy::{CaddyProxy, HealthCheckConfig, HealthChecker};
use caddy_tls::{AcmeManager, CertStorage, LETS_ENCRYPT_STAGING};
use clap::{Parser, Subcommand};
use pingora::prelude::*;
use pingora_proxy::http_proxy_service;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "caddy-rs")]
#[command(author, version, about = "A Caddy-like web server written in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Configuration file path
    #[arg(short, long, default_value = "caddy.toml")]
    config: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Test configuration and exit
    #[arg(short, long)]
    test: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the server
    Run {
        #[arg(short, long, default_value = "caddy.toml")]
        config: PathBuf,
    },
    /// Validate configuration
    Validate {
        #[arg(short, long, default_value = "caddy.toml")]
        config: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set tracing subscriber")?;

    match cli.command {
        Some(Commands::Validate { config }) => validate_config(config),
        Some(Commands::Run { config }) => run_server(config),
        None => {
            if cli.test {
                validate_config(cli.config)
            } else {
                run_server(cli.config)
            }
        }
    }
}

fn run_server(config_path: PathBuf) -> Result<()> {
    info!("Starting caddy-rs");
    info!(config = ?config_path, "Loading configuration");

    let config = Config::load(&config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    info!(servers = config.servers.len(), "Configuration loaded");

    // Initialize certificate storage
    let rt = tokio::runtime::Runtime::new()?;
    let storage = rt.block_on(async {
        CertStorage::new(&config.tls.storage_path).await
    }).context("Failed to initialize certificate storage")?;
    let storage = Arc::new(storage);

    // Initialize ACME manager
    let acme_ca = if config.tls.acme_ca.contains("staging") {
        LETS_ENCRYPT_STAGING
    } else {
        &config.tls.acme_ca
    };

    let acme_manager = AcmeManager::new(
        acme_ca.to_string(),
        config.tls.email.clone(),
        storage.clone(),
    );

    // Obtain certificates for TLS domains
    if config.tls.acme_enabled {
        let domains = config.get_tls_domains();
        if !domains.is_empty() {
            info!(domains = ?domains, "Checking certificates");

            rt.block_on(async {
                for domain in &domains {
                    match storage.load_cert(domain).await {
                        Ok(Some(bundle)) if !bundle.expires_within_days(30) => {
                            info!(domain = %domain, "Certificate valid");
                        }
                        _ => {
                            info!(domain = %domain, "Obtaining certificate");
                            if let Err(e) = acme_manager.obtain_certificate(domain).await {
                                warn!(domain = %domain, error = %e, "Failed to obtain certificate");
                            }
                        }
                    }
                }
            });
        }
    }

    // Create Pingora server
    let mut server = Server::new(None).context("Failed to create Pingora server")?;
    server.bootstrap();

    // Create proxy service
    let proxy = CaddyProxy::new(config.clone(), acme_manager.challenge_tokens())
        .context("Failed to create proxy")?;

    // Add listeners
    for server_config in &config.servers {
        for listen_addr in &server_config.listen {
            let mut service = http_proxy_service(&server.configuration, proxy.clone());

            let addr = if listen_addr.starts_with(':') {
                format!("0.0.0.0{}", listen_addr)
            } else {
                listen_addr.clone()
            };

            // Check for TLS listener
            if is_tls_address(listen_addr) {
                let domains = config.get_tls_domains();
                let first_domain = domains.first().cloned().unwrap_or_else(|| "localhost".to_string());

                if let Some((cert_path, key_path)) = get_tls_cert_paths(&config.tls.storage_path, &first_domain) {
                    let cert_str = cert_path.to_str().unwrap_or("");
                    let key_str = key_path.to_str().unwrap_or("");

                    match service.add_tls(&addr, cert_str, key_str) {
                        Ok(_) => {
                            info!(address = %addr, domain = %first_domain, "Listening (HTTPS)");
                        }
                        Err(e) => {
                            warn!(address = %addr, error = %e, "TLS failed, using HTTP");
                            service.add_tcp(&addr);
                            info!(address = %addr, "Listening (HTTP)");
                        }
                    }
                } else {
                    warn!(address = %addr, "No certificate, using HTTP");
                    service.add_tcp(&addr);
                    info!(address = %addr, "Listening (HTTP)");
                }
            } else {
                service.add_tcp(&addr);
                info!(address = %addr, server = %server_config.name, "Listening (HTTP)");
            }

            server.add_service(service);
        }
    }

    // Start health checkers
    start_health_checkers(&config, &proxy);

    info!("caddy-rs started successfully");
    server.run_forever();

    Ok(())
}

fn is_tls_address(addr: &str) -> bool {
    addr.contains(":443") || addr.starts_with("https://")
}

fn get_tls_cert_paths(storage_path: &PathBuf, domain: &str) -> Option<(PathBuf, PathBuf)> {
    let base = storage_path.join("certs").join(domain);
    let cert_path = base.with_extension("crt");
    let key_path = base.with_extension("key");

    if cert_path.exists() && key_path.exists() {
        Some((cert_path, key_path))
    } else {
        None
    }
}

fn start_health_checkers(config: &Config, proxy: &CaddyProxy) {
    for server_config in &config.servers {
        for route in &server_config.routes {
            if let HandlerConfig::ReverseProxy(proxy_config) = &route.handle {
                if let Some(health_config) = &proxy_config.health_check {
                    let upstreams = proxy.get_all_upstreams();

                    for selector in upstreams {
                        let servers = selector.servers();
                        let addresses: Vec<_> = servers.iter().map(|s| s.address_str.clone()).collect();

                        if proxy_config.upstreams.iter().all(|u| addresses.contains(u)) {
                            let check_config = HealthCheckConfig::from_config(health_config);
                            let checker = HealthChecker::new(servers.to_vec(), check_config);

                            info!(
                                upstreams = ?proxy_config.upstreams,
                                interval = ?health_config.interval,
                                "Starting health checker"
                            );

                            checker.start();
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn validate_config(config_path: PathBuf) -> Result<()> {
    let config = Config::load(&config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    println!("Configuration is valid!");
    println!("  Servers: {}", config.servers.len());

    for server in &config.servers {
        println!("  - {}: {} routes", server.name, server.routes.len());
        for addr in &server.listen {
            println!("    Listen: {}", addr);
        }
    }

    let domains = config.get_tls_domains();
    if !domains.is_empty() {
        println!("  TLS domains: {:?}", domains);
    }

    Ok(())
}
