//! Error types for avalon-proxy

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Upstream error: {0}")]
    UpstreamError(String),

    #[error("No healthy upstream available")]
    NoHealthyUpstream,

    #[error("Route not found")]
    RouteNotFound,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ProxyError>;
