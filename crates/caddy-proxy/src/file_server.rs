//! Static file server

use bytes::Bytes;
use http::StatusCode;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::debug;

/// File server response
pub struct FileResponse {
    pub status: StatusCode,
    pub content_type: String,
    pub body: Bytes,
    pub headers: Vec<(String, String)>,
}

/// Static file server
pub struct FileServer {
    root: PathBuf,
    browse: bool,
    index_files: Vec<String>,
}

impl FileServer {
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            browse: false,
            index_files: vec!["index.html".to_string(), "index.htm".to_string()],
        }
    }

    pub fn with_browse(mut self, browse: bool) -> Self {
        self.browse = browse;
        self
    }

    pub fn with_index_files(mut self, files: Vec<String>) -> Self {
        self.index_files = files;
        self
    }

    pub async fn serve(&self, path: &str) -> FileResponse {
        let sanitized = sanitize_path(path);

        // Check for path traversal
        if sanitized.contains("..") || is_hidden_path(&sanitized) {
            return self.error_response(StatusCode::FORBIDDEN, "Forbidden");
        }

        let full_path = self.root.join(&sanitized);

        if !full_path.starts_with(&self.root) {
            return self.error_response(StatusCode::FORBIDDEN, "Forbidden");
        }

        if full_path.is_dir() {
            // Try index files
            for index in &self.index_files {
                let index_path = full_path.join(index);
                if index_path.is_file() {
                    return self.serve_file(&index_path).await;
                }
            }

            // Directory listing
            if self.browse {
                return self.serve_directory(&full_path, path).await;
            } else {
                return self.error_response(StatusCode::FORBIDDEN, "Directory listing disabled");
            }
        }

        if full_path.is_file() {
            return self.serve_file(&full_path).await;
        }

        self.error_response(StatusCode::NOT_FOUND, "Not Found")
    }

    async fn serve_file(&self, path: &Path) -> FileResponse {
        match fs::read(path).await {
            Ok(content) => {
                let mime = mime_guess::from_path(path)
                    .first_or_octet_stream()
                    .to_string();

                debug!(path = ?path, mime = %mime, "Serving file");

                FileResponse {
                    status: StatusCode::OK,
                    content_type: mime,
                    body: Bytes::from(content),
                    headers: vec![],
                }
            }
            Err(_) => self.error_response(StatusCode::INTERNAL_SERVER_ERROR, "Read error"),
        }
    }

    async fn serve_directory(&self, path: &Path, url_path: &str) -> FileResponse {
        let mut entries = match fs::read_dir(path).await {
            Ok(e) => e,
            Err(_) => return self.error_response(StatusCode::INTERNAL_SERVER_ERROR, "Read error"),
        };

        let mut html = String::from("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
        html.push_str(&format!("<title>Index of {}</title></head><body>", url_path));
        html.push_str(&format!("<h1>Index of {}</h1><ul>", url_path));

        if url_path != "/" {
            html.push_str("<li><a href=\"..\">..</a></li>");
        }

        let mut items = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with('.') {
                let is_dir = entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
                items.push((name, is_dir));
            }
        }

        items.sort_by(|a, b| match (a.1, b.1) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.0.cmp(&b.0),
        });

        for (name, is_dir) in items {
            let display = if is_dir {
                format!("{}/", name)
            } else {
                name.clone()
            };
            let encoded = urlencoding::encode(&name);
            html.push_str(&format!("<li><a href=\"{}\">{}</a></li>", encoded, display));
        }

        html.push_str("</ul></body></html>");

        FileResponse {
            status: StatusCode::OK,
            content_type: "text/html; charset=utf-8".to_string(),
            body: Bytes::from(html),
            headers: vec![],
        }
    }

    fn error_response(&self, status: StatusCode, message: &str) -> FileResponse {
        FileResponse {
            status,
            content_type: "text/plain".to_string(),
            body: Bytes::from(format!("{} {}", status.as_u16(), message)),
            headers: vec![],
        }
    }
}

fn sanitize_path(path: &str) -> String {
    let path = path.trim_start_matches('/');
    path.replace("//", "/")
}

fn is_hidden_path(path: &str) -> bool {
    path.split('/').any(|segment| segment.starts_with('.') && segment != "." && segment != "..")
}

fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size >= GB {
        format!("{:.1} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.1} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.1} KB", size as f64 / KB as f64)
    } else {
        format!("{} B", size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_sanitize_path() {
        assert_eq!(sanitize_path("/test"), "test");
        assert_eq!(sanitize_path("//test//file"), "test/file");
        assert_eq!(sanitize_path("/"), "");
    }

    #[test]
    fn test_is_hidden_path() {
        assert!(is_hidden_path(".hidden"));
        assert!(is_hidden_path("dir/.hidden"));
        assert!(!is_hidden_path("normal"));
        assert!(!is_hidden_path("dir/normal"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(100), "100 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
    }

    #[tokio::test]
    async fn test_serve_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"Hello, World!").unwrap();

        let server = FileServer::new(temp_dir.path());
        let response = server.serve("/test.txt").await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.content_type, "text/plain");
        assert_eq!(response.body.as_ref(), b"Hello, World!");
    }

    #[tokio::test]
    async fn test_serve_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let server = FileServer::new(temp_dir.path());
        let response = server.serve("/nonexistent.txt").await;

        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_serve_index() {
        let temp_dir = TempDir::new().unwrap();
        let index_path = temp_dir.path().join("index.html");
        let mut file = File::create(&index_path).unwrap();
        file.write_all(b"<html>Index</html>").unwrap();

        let server = FileServer::new(temp_dir.path());
        let response = server.serve("/").await;

        assert_eq!(response.status, StatusCode::OK);
        assert!(response.content_type.contains("text/html"));
    }

    #[tokio::test]
    async fn test_serve_directory_forbidden() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir(temp_dir.path().join("subdir")).unwrap();

        let server = FileServer::new(temp_dir.path()).with_browse(false);
        let response = server.serve("/subdir").await;

        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_serve_directory_browse() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir(temp_dir.path().join("subdir")).unwrap();
        File::create(temp_dir.path().join("subdir").join("file.txt")).unwrap();

        let server = FileServer::new(temp_dir.path()).with_browse(true);
        let response = server.serve("/subdir").await;

        assert_eq!(response.status, StatusCode::OK);
        assert!(response.content_type.contains("text/html"));
        assert!(String::from_utf8_lossy(&response.body).contains("file.txt"));
    }

    #[tokio::test]
    async fn test_path_traversal_blocked() {
        let temp_dir = TempDir::new().unwrap();
        let server = FileServer::new(temp_dir.path());
        let response = server.serve("/../../../etc/passwd").await;

        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_hidden_files_blocked() {
        let temp_dir = TempDir::new().unwrap();
        File::create(temp_dir.path().join(".hidden")).unwrap();

        let server = FileServer::new(temp_dir.path());
        let response = server.serve("/.hidden").await;

        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }
}
