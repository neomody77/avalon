//! Response compression support (gzip, brotli)

use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;
use tracing::debug;

/// Compression encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionEncoding {
    Gzip,
    Brotli,
    Identity,
}

impl CompressionEncoding {
    /// Get the Content-Encoding header value
    pub fn header_value(&self) -> &'static str {
        match self {
            CompressionEncoding::Gzip => "gzip",
            CompressionEncoding::Brotli => "br",
            CompressionEncoding::Identity => "identity",
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Enable gzip compression
    pub gzip: bool,
    /// Enable brotli compression
    pub brotli: bool,
    /// Minimum response size to compress (bytes)
    pub min_size: usize,
    /// Compression level (1-9 for gzip, 0-11 for brotli)
    pub level: u32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            gzip: true,
            brotli: true,
            min_size: 1024, // Don't compress responses smaller than 1KB
            level: 6,
        }
    }
}

/// Parsed encoding with quality factor
#[derive(Debug, Clone)]
struct EncodingQuality {
    encoding: &'static str,
    quality: f32,
}

/// Parse Accept-Encoding header and select best encoding according to RFC 7231 Section 5.3.4
pub fn select_encoding(accept_encoding: Option<&str>, config: &CompressionConfig) -> CompressionEncoding {
    let accept = match accept_encoding {
        Some(ae) => ae,
        None => return CompressionEncoding::Identity,
    };

    // Parse all encodings with their quality factors
    let mut encodings: Vec<EncodingQuality> = Vec::new();
    let mut wildcard_quality: Option<f32> = None;

    for part in accept.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (encoding, quality) = parse_encoding_quality(part);
        let encoding_lower = encoding.to_lowercase();

        if encoding_lower == "*" {
            wildcard_quality = Some(quality);
        } else if encoding_lower == "br" || encoding_lower == "gzip" || encoding_lower == "identity" {
            encodings.push(EncodingQuality {
                encoding: match encoding_lower.as_str() {
                    "br" => "br",
                    "gzip" => "gzip",
                    "identity" => "identity",
                    _ => continue,
                },
                quality,
            });
        }
    }

    // Sort by quality (descending), then by server preference (br > gzip > identity)
    // Server preference order: br (best compression) > gzip > identity
    fn encoding_preference(enc: &str) -> u8 {
        match enc {
            "br" => 0,      // Most preferred
            "gzip" => 1,
            "identity" => 2,
            _ => 3,
        }
    }
    encodings.sort_by(|a, b| {
        match b.quality.partial_cmp(&a.quality) {
            Some(std::cmp::Ordering::Equal) | None => {
                // When quality is equal, use server preference
                encoding_preference(a.encoding).cmp(&encoding_preference(b.encoding))
            }
            Some(ord) => ord,
        }
    });

    // Check if identity is explicitly rejected (q=0)
    let identity_rejected = encodings.iter().any(|e| e.encoding == "identity" && e.quality == 0.0)
        || (wildcard_quality == Some(0.0) && !encodings.iter().any(|e| e.encoding == "identity" && e.quality > 0.0));

    // Select best encoding that is enabled and not rejected (q=0)
    for enc in &encodings {
        if enc.quality == 0.0 {
            continue; // Explicitly rejected
        }

        match enc.encoding {
            "br" if config.brotli => return CompressionEncoding::Brotli,
            "gzip" if config.gzip => return CompressionEncoding::Gzip,
            "identity" => return CompressionEncoding::Identity,
            _ => continue,
        }
    }

    // If wildcard is present with quality > 0, use best available encoding
    if let Some(q) = wildcard_quality {
        if q > 0.0 {
            if config.brotli && !encodings.iter().any(|e| e.encoding == "br" && e.quality == 0.0) {
                return CompressionEncoding::Brotli;
            }
            if config.gzip && !encodings.iter().any(|e| e.encoding == "gzip" && e.quality == 0.0) {
                return CompressionEncoding::Gzip;
            }
        }
    }

    // Default to identity if not rejected
    if identity_rejected {
        // Client rejects identity - this is technically a 406 Not Acceptable situation
        // but we'll return Identity anyway and let the caller decide
        CompressionEncoding::Identity
    } else {
        CompressionEncoding::Identity
    }
}

/// Parse encoding and quality factor from a single Accept-Encoding part
/// Example: "gzip;q=0.8" -> ("gzip", 0.8)
fn parse_encoding_quality(s: &str) -> (&str, f32) {
    let parts: Vec<&str> = s.splitn(2, ';').collect();
    let encoding = parts[0].trim();

    let quality = if parts.len() > 1 {
        let q_part = parts[1].trim();
        if let Some(q_str) = q_part.strip_prefix("q=").or_else(|| q_part.strip_prefix("Q=")) {
            q_str.trim().parse::<f32>().unwrap_or(1.0).clamp(0.0, 1.0)
        } else {
            1.0
        }
    } else {
        1.0
    };

    (encoding, quality)
}

/// Check if content type should be compressed
pub fn should_compress_content_type(content_type: Option<&str>) -> bool {
    let ct = match content_type {
        Some(ct) => ct.to_lowercase(),
        None => return false,
    };

    // Compress text-based content types
    ct.starts_with("text/")
        || ct.contains("application/json")
        || ct.contains("application/xml")
        || ct.contains("application/javascript")
        || ct.contains("application/x-javascript")
        || ct.contains("application/ecmascript")
        || ct.contains("application/rss+xml")
        || ct.contains("application/atom+xml")
        || ct.contains("image/svg+xml")
        || ct.contains("application/xhtml+xml")
        || ct.contains("application/x-yaml")
        || ct.contains("application/yaml")
}

/// Check if response is already compressed
/// Properly parses Content-Encoding header per RFC 7231 Section 3.1.2.2
pub fn is_already_compressed(content_encoding: Option<&str>) -> bool {
    let ce = match content_encoding {
        Some(ce) => ce,
        None => return false,
    };

    // Content-Encoding is a comma-separated list of encodings
    for encoding in ce.split(',') {
        let encoding = encoding.trim().to_lowercase();
        match encoding.as_str() {
            "gzip" | "x-gzip" | "br" | "deflate" | "compress" | "x-compress" | "zstd" => {
                return true;
            }
            _ => continue,
        }
    }
    false
}

/// Compress data using gzip
pub fn compress_gzip(data: &[u8], level: u32) -> Result<Bytes, std::io::Error> {
    let level = level.min(9);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data)?;
    let compressed = encoder.finish()?;

    debug!(
        original_size = data.len(),
        compressed_size = compressed.len(),
        ratio = format!("{:.1}%", (compressed.len() as f64 / data.len() as f64) * 100.0),
        "Gzip compression"
    );

    Ok(Bytes::from(compressed))
}

/// Compress data using brotli
pub fn compress_brotli(data: &[u8], level: u32) -> Result<Bytes, std::io::Error> {
    let level = level.min(11);
    let mut compressed = Vec::new();

    let params = brotli::enc::BrotliEncoderParams {
        quality: level as i32,
        ..Default::default()
    };

    let mut encoder = brotli::CompressorWriter::with_params(&mut compressed, 4096, &params);
    encoder.write_all(data)?;
    drop(encoder); // Flush and finish

    debug!(
        original_size = data.len(),
        compressed_size = compressed.len(),
        ratio = format!("{:.1}%", (compressed.len() as f64 / data.len() as f64) * 100.0),
        "Brotli compression"
    );

    Ok(Bytes::from(compressed))
}

/// Compress data with the specified encoding
pub fn compress(data: &[u8], encoding: CompressionEncoding, level: u32) -> Result<Bytes, std::io::Error> {
    match encoding {
        CompressionEncoding::Gzip => compress_gzip(data, level),
        CompressionEncoding::Brotli => compress_brotli(data, level),
        CompressionEncoding::Identity => Ok(Bytes::copy_from_slice(data)),
    }
}

/// Response compressor that handles chunked responses
pub struct ResponseCompressor {
    encoding: CompressionEncoding,
    config: CompressionConfig,
    buffer: Vec<u8>,
    finalized: bool,
}

impl ResponseCompressor {
    pub fn new(encoding: CompressionEncoding, config: CompressionConfig) -> Self {
        Self {
            encoding,
            config,
            buffer: Vec::new(),
            finalized: false,
        }
    }

    /// Add data to the compression buffer
    pub fn write(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Finalize and get compressed data
    pub fn finish(&mut self) -> Result<Bytes, std::io::Error> {
        if self.finalized {
            return Ok(Bytes::new());
        }
        self.finalized = true;

        // Skip compression if data is too small
        if self.buffer.len() < self.config.min_size {
            return Ok(Bytes::copy_from_slice(&self.buffer));
        }

        compress(&self.buffer, self.encoding, self.config.level)
    }

    /// Get the encoding used
    pub fn encoding(&self) -> CompressionEncoding {
        self.encoding
    }

    /// Check if compression will be applied
    pub fn will_compress(&self) -> bool {
        self.encoding != CompressionEncoding::Identity && self.buffer.len() >= self.config.min_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_encoding_brotli() {
        let config = CompressionConfig::default();
        let encoding = select_encoding(Some("gzip, deflate, br"), &config);
        assert_eq!(encoding, CompressionEncoding::Brotli);
    }

    #[test]
    fn test_select_encoding_gzip() {
        let config = CompressionConfig {
            brotli: false,
            ..Default::default()
        };
        let encoding = select_encoding(Some("gzip, deflate, br"), &config);
        assert_eq!(encoding, CompressionEncoding::Gzip);
    }

    #[test]
    fn test_select_encoding_none() {
        let config = CompressionConfig::default();
        let encoding = select_encoding(None, &config);
        assert_eq!(encoding, CompressionEncoding::Identity);
    }

    #[test]
    fn test_select_encoding_quality_factors() {
        let config = CompressionConfig::default();

        // Prefer gzip when it has higher quality
        let encoding = select_encoding(Some("gzip;q=1.0, br;q=0.5"), &config);
        assert_eq!(encoding, CompressionEncoding::Gzip);

        // Prefer brotli when it has higher quality
        let encoding = select_encoding(Some("gzip;q=0.5, br;q=1.0"), &config);
        assert_eq!(encoding, CompressionEncoding::Brotli);

        // Reject gzip with q=0
        let config_gzip_only = CompressionConfig {
            brotli: false,
            ..Default::default()
        };
        let encoding = select_encoding(Some("gzip;q=0"), &config_gzip_only);
        assert_eq!(encoding, CompressionEncoding::Identity);
    }

    #[test]
    fn test_select_encoding_wildcard() {
        let config = CompressionConfig::default();

        // Wildcard should select best available
        let encoding = select_encoding(Some("*"), &config);
        assert_eq!(encoding, CompressionEncoding::Brotli);

        // Wildcard with br explicitly rejected
        let encoding = select_encoding(Some("*, br;q=0"), &config);
        assert_eq!(encoding, CompressionEncoding::Gzip);

        // Wildcard q=0 rejects all not explicitly listed
        let encoding = select_encoding(Some("*;q=0, gzip;q=1.0"), &config);
        assert_eq!(encoding, CompressionEncoding::Gzip);
    }

    #[test]
    fn test_select_encoding_identity_rejected() {
        let config = CompressionConfig {
            gzip: false,
            brotli: false,
            ..Default::default()
        };

        // Even with identity rejected, we return Identity (caller handles 406)
        let encoding = select_encoding(Some("identity;q=0"), &config);
        assert_eq!(encoding, CompressionEncoding::Identity);
    }

    #[test]
    fn test_should_compress_content_type() {
        assert!(should_compress_content_type(Some("text/html")));
        assert!(should_compress_content_type(Some("application/json")));
        assert!(should_compress_content_type(Some("text/css")));
        assert!(should_compress_content_type(Some("application/javascript")));
        assert!(should_compress_content_type(Some("image/svg+xml")));

        assert!(!should_compress_content_type(Some("image/png")));
        assert!(!should_compress_content_type(Some("image/jpeg")));
        assert!(!should_compress_content_type(Some("application/octet-stream")));
        assert!(!should_compress_content_type(None));
    }

    #[test]
    fn test_is_already_compressed() {
        assert!(is_already_compressed(Some("gzip")));
        assert!(is_already_compressed(Some("br")));
        assert!(is_already_compressed(Some("deflate")));
        assert!(is_already_compressed(Some("zstd")));
        assert!(is_already_compressed(Some("x-gzip")));
        assert!(is_already_compressed(Some("gzip, br"))); // Multiple encodings
        assert!(!is_already_compressed(Some("identity")));
        assert!(!is_already_compressed(Some("chunked"))); // Transfer-Encoding, not Content-Encoding
        assert!(!is_already_compressed(None));
    }

    #[test]
    fn test_compress_gzip() {
        let data = b"Hello, World! This is a test string for compression.";
        let compressed = compress_gzip(data, 6).unwrap();
        assert!(!compressed.is_empty());
        // Compressed data should generally be different (though small data may not compress well)
    }

    #[test]
    fn test_compress_brotli() {
        let data = b"Hello, World! This is a test string for compression.";
        let compressed = compress_brotli(data, 6).unwrap();
        assert!(!compressed.is_empty());
    }

    #[test]
    fn test_response_compressor() {
        let config = CompressionConfig {
            min_size: 10,
            ..Default::default()
        };
        let mut compressor = ResponseCompressor::new(CompressionEncoding::Gzip, config);

        compressor.write(b"Hello, World! This is a test string that should be compressed.");
        let result = compressor.finish().unwrap();

        assert!(!result.is_empty());
    }

    #[test]
    fn test_response_compressor_skip_small() {
        let config = CompressionConfig {
            min_size: 1000,
            ..Default::default()
        };
        let mut compressor = ResponseCompressor::new(CompressionEncoding::Gzip, config);

        compressor.write(b"Small");
        let result = compressor.finish().unwrap();

        // Small data should not be compressed
        assert_eq!(result.as_ref(), b"Small");
    }
}
