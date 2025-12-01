//! avalon: A Avalon-like web server written in Rust
//!
//! Built on Cloudflare's Pingora framework for high-performance
//! reverse proxying with automatic HTTPS via Let's Encrypt.

use anyhow::{Context, Result};
use config::{Config, HandlerConfig};
use proxy::{AvalonProxy, HealthCheckConfig, HealthChecker, wait_for_connections_drain};
use tls::{
    AcmeManager, CertStorage, RenewalScheduler, auto_select_certificate, get_acme_ca_name,
    resolve_acme_ca, shutdown_channel,
};
use clap::{Parser, Subcommand};
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Config as NotifyConfig};
use pingora::prelude::*;
use pingora_proxy::http_proxy_service;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::time::Duration;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

mod telemetry;

#[derive(Parser)]
#[command(name = "avalon")]
#[command(author, version, about = "A Avalon-like web server written in Rust")]
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

    /// Watch config file and auto-reload on changes
    #[arg(short, long)]
    watch: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the server
    Run {
        #[arg(short, long, default_value = "caddy.toml")]
        config: PathBuf,
        /// Watch config file and auto-reload on changes
        #[arg(short, long)]
        watch: bool,
    },
    /// Validate configuration
    Validate {
        #[arg(short, long, default_value = "caddy.toml")]
        config: PathBuf,
    },
}

fn main() -> Result<()> {
    // Install rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

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
        Some(Commands::Run { config, watch }) => run_server(config, watch),
        None => {
            if cli.test {
                validate_config(cli.config)
            } else {
                run_server(cli.config, cli.watch)
            }
        }
    }
}

#[allow(unreachable_code)]
fn run_server(config_path: PathBuf, watch_config: bool) -> Result<()> {
    info!("Starting avalon");
    info!(config = ?config_path, watch = watch_config, "Loading configuration");

    let config = Config::load(&config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    info!(servers = config.servers.len(), "Configuration loaded");

    // Initialize OpenTelemetry tracing if enabled
    let telemetry_provider = telemetry::init_telemetry(&config.global.tracing);

    // Initialize certificate storage
    let rt = tokio::runtime::Runtime::new()?;
    let storage = rt.block_on(async {
        CertStorage::new(&config.tls.storage_path).await
    }).context("Failed to initialize certificate storage")?;
    let storage = Arc::new(storage);

    // Initialize ACME manager with provider resolution
    // Supports provider names (e.g., "letsencrypt", "zerossl", "google") or direct URLs
    let acme_ca = resolve_acme_ca(&config.tls.acme_ca);
    let ca_name = get_acme_ca_name(&acme_ca);
    info!(provider = %ca_name, url = %acme_ca, "Using ACME CA");

    let acme_manager = AcmeManager::new(
        acme_ca,
        config.tls.email.clone(),
        storage.clone(),
    );

    // Check if we have valid certificates (don't obtain yet - server needs to be running first)
    let mut needs_cert = Vec::new();
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
                            info!(domain = %domain, "Certificate needed");
                            needs_cert.push(domain.clone());
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
    let proxy = AvalonProxy::new(config.clone(), acme_manager.challenge_tokens())
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
                info!(domains = ?domains, "TLS domains found");
                let first_domain = domains.first().cloned().unwrap_or_else(|| "localhost".to_string());
                info!(domain = %first_domain, storage_path = ?config.tls.storage_path, "Looking for certificate");

                if let Some((cert_path, key_path)) = get_tls_cert_paths(&config.tls, &first_domain) {
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

    // Create shutdown channel for graceful shutdown
    let (shutdown_tx, shutdown_rx) = shutdown_channel();

    // Spawn background ACME certificate acquisition (after server starts)
    // Use Arc to share the same acme_manager (and its challenge_tokens) with the background thread
    let acme_manager = Arc::new(acme_manager);
    if !needs_cert.is_empty() {
        let acme_manager_bg = acme_manager.clone();
        std::thread::spawn(move || {
            // Wait for server to start listening
            std::thread::sleep(std::time::Duration::from_secs(3));

            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to create tokio runtime for ACME");
                    return;
                }
            };
            rt.block_on(async {
                for domain in needs_cert {
                    info!(domain = %domain, "Obtaining certificate via ACME (background)");
                    match acme_manager_bg.obtain_certificate(&domain).await {
                        Ok(_) => info!(domain = %domain, "Certificate obtained successfully"),
                        Err(e) => warn!(domain = %domain, error = %e, "Failed to obtain certificate"),
                    }
                }
            });
        });
    }

    // Start certificate renewal scheduler
    let domains = config.get_tls_domains();
    if config.tls.acme_enabled && !domains.is_empty() {
        let acme_manager_renewal = acme_manager.clone();
        let storage_renewal = storage.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to create tokio runtime for renewal scheduler");
                    return;
                }
            };
            rt.block_on(async {
                let scheduler = RenewalScheduler::new(
                    acme_manager_renewal,
                    storage_renewal,
                    domains,
                    shutdown_rx,
                );
                info!("Starting certificate renewal scheduler");
                scheduler.start().await.ok();
            });
        });
    }

    // Setup signal handler for graceful shutdown
    let shutdown_tx_clone = shutdown_tx.clone();
    let grace_period = Duration::from_secs(config.global.grace_period);
    ctrlc::set_handler(move || {
        info!("Received shutdown signal, initiating graceful shutdown...");

        // Notify other components (renewal scheduler, etc.) to stop
        let _ = shutdown_tx_clone.send(true);

        // Wait for active connections to drain (with timeout)
        info!(grace_period_secs = grace_period.as_secs(), "Waiting for connections to drain...");
        if wait_for_connections_drain(grace_period) {
            info!("All connections drained successfully");
        } else {
            warn!("Grace period expired, some connections may be terminated");
        }

        // Exit the process after draining (Pingora will also handle its own cleanup)
        info!("Shutdown complete");
        std::process::exit(0);
    }).ok();

    // Store telemetry provider to keep it alive for the duration of the server
    // It will be automatically shut down when the process exits
    let _telemetry_guard = telemetry_provider;

    // Start config file watcher if enabled
    if watch_config {
        let proxy_for_reload = proxy.clone();
        let config_path_for_watch = config_path.clone();
        std::thread::spawn(move || {
            if let Err(e) = start_config_watcher(config_path_for_watch, proxy_for_reload) {
                error!(error = %e, "Config watcher failed");
            }
        });
        info!("Config file watcher enabled - changes will trigger auto-reload");
    }

    info!("avalon started successfully");
    server.run_forever();

    Ok(())
}

fn is_tls_address(addr: &str) -> bool {
    addr.contains(":443") || addr.starts_with("https://")
}

fn get_tls_cert_paths(
    tls_config: &config::TlsConfig,
    domain: &str,
) -> Option<(PathBuf, PathBuf)> {
    let storage_path = &tls_config.storage_path;

    // 1. First check explicit config (cert_path/key_path)
    if let (Some(cert_path), Some(key_path)) = (&tls_config.cert_path, &tls_config.key_path) {
        if cert_path.exists() && key_path.exists() {
            info!(
                cert = ?cert_path, key = ?key_path,
                "Using explicitly configured certificate"
            );
            return Some((cert_path.clone(), key_path.clone()));
        } else {
            warn!(
                cert = ?cert_path, key = ?key_path,
                "Explicit certificate paths configured but files not found"
            );
        }
    }

    // 2. Auto-discover certificates in storage_path and current working directory
    info!(domain = %domain, "Trying auto-discovery");

    // Search in storage_path
    if let Some(paths) = auto_select_certificate(storage_path, domain) {
        info!(domain = %domain, cert = ?paths.0, key = ?paths.1, "Auto-discovered certificate in storage path");
        return Some(paths);
    }

    // Search in current working directory
    if let Ok(cwd) = std::env::current_dir() {
        if cwd != *storage_path {
            if let Some(paths) = auto_select_certificate(&cwd, domain) {
                info!(domain = %domain, cert = ?paths.0, key = ?paths.1, "Auto-discovered certificate in working directory");
                return Some(paths);
            }
        }
    }

    // 3. Try ACME stored certs (storage_path/certs/{domain}.crt)
    // Note: Don't use with_extension() as it replaces after the last dot
    // (e.g., "api-a.hater.cc" would become "api-a.hater.crt")
    let cert_path = storage_path.join("certs").join(format!("{}.crt", domain));
    let key_path = storage_path.join("certs").join(format!("{}.key", domain));

    info!(cert_path = ?cert_path, key_path = ?key_path,
          cert_exists = cert_path.exists(), key_exists = key_path.exists(),
          "Checking ACME cert path");

    if cert_path.exists() && key_path.exists() {
        return Some((cert_path, key_path));
    }

    // 4. Try storage_path/{domain}.crt (manual/self-signed certs)
    let cert_path = storage_path.join(format!("{}.crt", domain));
    let key_path = storage_path.join(format!("{}.key", domain));

    info!(cert_path = ?cert_path, key_path = ?key_path,
          cert_exists = cert_path.exists(), key_exists = key_path.exists(),
          "Checking manual cert path");

    if cert_path.exists() && key_path.exists() {
        return Some((cert_path, key_path));
    }

    None
}

fn start_health_checkers(config: &Config, proxy: &AvalonProxy) {
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

fn start_config_watcher(config_path: PathBuf, proxy: AvalonProxy) -> Result<()> {
    use notify::event::{EventKind, ModifyKind};

    let (tx, rx) = channel();

    let config = NotifyConfig::default()
        .with_poll_interval(Duration::from_secs(2));

    let mut watcher: RecommendedWatcher = Watcher::new(tx, config)
        .context("Failed to create file watcher")?;

    watcher.watch(&config_path, RecursiveMode::NonRecursive)
        .with_context(|| format!("Failed to watch config file: {:?}", config_path))?;

    info!(path = ?config_path, "Watching config file for changes");

    let mut last_reload = std::time::Instant::now();
    let debounce_duration = Duration::from_millis(500);

    loop {
        match rx.recv() {
            Ok(Ok(event)) => {
                // Only react to modify events
                let should_reload = match event.kind {
                    EventKind::Modify(ModifyKind::Data(_)) => true,
                    EventKind::Modify(ModifyKind::Any) => true,
                    _ => false,
                };

                if should_reload {
                    // Debounce - avoid rapid reloads
                    let now = std::time::Instant::now();
                    if now.duration_since(last_reload) < debounce_duration {
                        continue;
                    }
                    last_reload = now;

                    info!("Config file changed, reloading...");

                    // Small delay to ensure file is fully written
                    std::thread::sleep(Duration::from_millis(100));

                    match Config::load(&config_path) {
                        Ok(new_config) => {
                            match proxy.reload_config(new_config) {
                                Ok(_) => info!("Configuration reloaded successfully"),
                                Err(e) => error!(error = %e, "Failed to apply new configuration"),
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to parse new configuration, keeping old config");
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                error!(error = %e, "Watch error");
            }
            Err(e) => {
                error!(error = %e, "Channel receive error");
                break;
            }
        }
    }

    Ok(())
}
