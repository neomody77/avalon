//! TLS error types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ACME error: {0}")]
    Acme(String),

    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[error("Certificate generation error: {0}")]
    CertGeneration(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
