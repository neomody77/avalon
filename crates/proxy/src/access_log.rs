//! Access logging for HTTP requests

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;

/// Access log entry data
#[derive(Debug, Clone)]
pub struct AccessLogEntry {
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub host: String,
    pub status: u16,
    pub bytes_sent: u64,
    pub user_agent: String,
    pub referer: String,
    pub duration_ms: u64,
    pub is_websocket: bool,
}

/// Log format type
#[derive(Debug, Clone, Default, PartialEq)]
pub enum LogFormat {
    /// Apache Common Log Format
    #[default]
    Common,
    /// Apache Combined Log Format
    Combined,
    /// JSON format
    Json,
}

impl std::str::FromStr for LogFormat {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "combined" => LogFormat::Combined,
            "json" => LogFormat::Json,
            _ => LogFormat::Common,
        })
    }
}

/// Access logger that writes to a file
pub struct AccessLogger {
    writer: Arc<Mutex<BufWriter<File>>>,
    format: LogFormat,
}

impl AccessLogger {
    /// Create a new access logger
    pub fn new<P: AsRef<Path>>(path: P, format: LogFormat) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        let writer = BufWriter::new(file);

        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            format,
        })
    }

    /// Log an access entry
    pub fn log(&self, entry: &AccessLogEntry) {
        let line = match self.format {
            LogFormat::Common => self.format_common(entry),
            LogFormat::Combined => self.format_combined(entry),
            LogFormat::Json => self.format_json(entry),
        };

        let mut writer = self.writer.lock();
        let _ = writeln!(writer, "{}", line);
        let _ = writer.flush();
    }

    /// Format entry in Common Log Format
    /// 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    fn format_common(&self, entry: &AccessLogEntry) -> String {
        let timestamp = entry.timestamp.format("%d/%b/%Y:%H:%M:%S %z");
        format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} {}",
            entry.client_ip,
            timestamp,
            entry.method,
            entry.path,
            entry.status,
            entry.bytes_sent
        )
    }

    /// Format entry in Combined Log Format
    /// Common + Referer + User-Agent
    fn format_combined(&self, entry: &AccessLogEntry) -> String {
        let timestamp = entry.timestamp.format("%d/%b/%Y:%H:%M:%S %z");
        format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\"",
            entry.client_ip,
            timestamp,
            entry.method,
            entry.path,
            entry.status,
            entry.bytes_sent,
            entry.referer,
            entry.user_agent
        )
    }

    /// Format entry as JSON
    fn format_json(&self, entry: &AccessLogEntry) -> String {
        format!(
            r#"{{"timestamp":"{}","client_ip":"{}","method":"{}","path":"{}","host":"{}","status":{},"bytes_sent":{},"user_agent":"{}","referer":"{}","duration_ms":{},"websocket":{}}}"#,
            entry.timestamp.to_rfc3339(),
            escape_json(&entry.client_ip),
            escape_json(&entry.method),
            escape_json(&entry.path),
            escape_json(&entry.host),
            entry.status,
            entry.bytes_sent,
            escape_json(&entry.user_agent),
            escape_json(&entry.referer),
            entry.duration_ms,
            entry.is_websocket
        )
    }
}

impl Clone for AccessLogger {
    fn clone(&self) -> Self {
        Self {
            writer: self.writer.clone(),
            format: self.format.clone(),
        }
    }
}

/// Escape special characters for JSON strings
fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    fn make_test_entry() -> AccessLogEntry {
        AccessLogEntry {
            timestamp: Utc::now(),
            client_ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            host: "example.com".to_string(),
            status: 200,
            bytes_sent: 1234,
            user_agent: "Mozilla/5.0".to_string(),
            referer: "https://example.com".to_string(),
            duration_ms: 42,
            is_websocket: false,
        }
    }

    #[test]
    fn test_log_format_from_str() {
        assert_eq!("common".parse::<LogFormat>().unwrap(), LogFormat::Common);
        assert_eq!("combined".parse::<LogFormat>().unwrap(), LogFormat::Combined);
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("unknown".parse::<LogFormat>().unwrap(), LogFormat::Common);
    }

    #[test]
    fn test_format_common() {
        let logger = {
            let tmp = NamedTempFile::new().unwrap();
            AccessLogger::new(tmp.path(), LogFormat::Common).unwrap()
        };

        let entry = make_test_entry();
        let line = logger.format_common(&entry);

        assert!(line.contains("127.0.0.1"));
        assert!(line.contains("GET /api/test HTTP/1.1"));
        assert!(line.contains("200"));
        assert!(line.contains("1234"));
    }

    #[test]
    fn test_format_combined() {
        let logger = {
            let tmp = NamedTempFile::new().unwrap();
            AccessLogger::new(tmp.path(), LogFormat::Combined).unwrap()
        };

        let entry = make_test_entry();
        let line = logger.format_combined(&entry);

        assert!(line.contains("127.0.0.1"));
        assert!(line.contains("Mozilla/5.0"));
        assert!(line.contains("https://example.com"));
    }

    #[test]
    fn test_format_json() {
        let logger = {
            let tmp = NamedTempFile::new().unwrap();
            AccessLogger::new(tmp.path(), LogFormat::Json).unwrap()
        };

        let entry = make_test_entry();
        let line = logger.format_json(&entry);

        assert!(line.contains("\"method\":\"GET\""));
        assert!(line.contains("\"status\":200"));
        assert!(line.contains("\"websocket\":false"));
    }

    #[test]
    fn test_escape_json() {
        assert_eq!(escape_json("hello"), "hello");
        assert_eq!(escape_json("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json("line\nbreak"), "line\\nbreak");
        assert_eq!(escape_json("tab\there"), "tab\\there");
    }

    #[test]
    fn test_logger_write() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();

        {
            let logger = AccessLogger::new(&path, LogFormat::Common).unwrap();
            let entry = make_test_entry();
            logger.log(&entry);
        }

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("GET /api/test"));
    }
}
