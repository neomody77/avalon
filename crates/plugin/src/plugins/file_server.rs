//! File Server Plugin
//!
//! Serves static files from a directory with directory listing support.

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{EarlyRequestHook, HookAction, RequestInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use serde::Deserialize;
use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// File server plugin configuration
#[derive(Debug, Clone, Deserialize)]
pub struct FileServerPluginConfig {
    /// Root directory to serve files from
    pub root: String,
    /// Index files to look for in directories
    #[serde(default = "default_index_files")]
    pub index_files: Vec<String>,
    /// Enable directory listing
    #[serde(default)]
    pub browse: bool,
    /// Hide dot files
    #[serde(default = "default_true")]
    pub hide_dot_files: bool,
    /// Enable ETag headers
    #[serde(default = "default_true")]
    pub etag: bool,
    /// Canonical URIs (redirect /dir to /dir/)
    #[serde(default = "default_true")]
    pub canonical_uris: bool,
}

fn default_index_files() -> Vec<String> {
    vec!["index.html".to_string(), "index.htm".to_string()]
}

fn default_true() -> bool {
    true
}

impl Default for FileServerPluginConfig {
    fn default() -> Self {
        Self {
            root: ".".to_string(),
            index_files: default_index_files(),
            browse: false,
            hide_dot_files: true,
            etag: true,
            canonical_uris: true,
        }
    }
}

/// Resolved file information
#[derive(Debug, Clone)]
pub struct ResolvedFile {
    pub path: PathBuf,
    pub is_directory: bool,
    pub content_type: String,
    pub size: u64,
    pub modified: Option<std::time::SystemTime>,
}

/// File server state
struct FileServerState {
    config: FileServerPluginConfig,
    root: PathBuf,
}

impl FileServerState {
    fn new(config: FileServerPluginConfig) -> Result<Self> {
        let root = PathBuf::from(&config.root);
        if !root.exists() {
            return Err(PluginError::ConfigError(format!(
                "Root directory does not exist: {}",
                config.root
            )));
        }
        Ok(Self { config, root })
    }

    fn resolve_path(&self, request_path: &str) -> Option<ResolvedFile> {
        // Sanitize path - prevent directory traversal
        let clean_path = self.sanitize_path(request_path)?;
        let full_path = self.root.join(&clean_path);

        // Check if path escapes root
        if !self.is_within_root(&full_path) {
            return None;
        }

        // Check dot files
        if self.config.hide_dot_files && self.contains_dot_file(&clean_path) {
            return None;
        }

        // Check if file/dir exists
        if !full_path.exists() {
            return None;
        }

        let metadata = full_path.metadata().ok()?;

        if metadata.is_dir() {
            // Try index files
            for index in &self.config.index_files {
                let index_path = full_path.join(index);
                if index_path.exists() && index_path.is_file() {
                    let index_meta = index_path.metadata().ok()?;
                    return Some(ResolvedFile {
                        path: index_path.clone(),
                        is_directory: false,
                        content_type: self.guess_content_type(&index_path),
                        size: index_meta.len(),
                        modified: index_meta.modified().ok(),
                    });
                }
            }
            // Return directory for listing
            if self.config.browse {
                return Some(ResolvedFile {
                    path: full_path,
                    is_directory: true,
                    content_type: "text/html".to_string(),
                    size: 0,
                    modified: metadata.modified().ok(),
                });
            }
            return None;
        }

        Some(ResolvedFile {
            path: full_path.clone(),
            is_directory: false,
            content_type: self.guess_content_type(&full_path),
            size: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }

    fn sanitize_path(&self, path: &str) -> Option<String> {
        // Remove leading slash
        let path = path.trim_start_matches('/');

        // Split and filter path components
        let mut components = Vec::new();
        for part in path.split('/') {
            match part {
                "" | "." => continue,
                ".." => {
                    // Prevent directory traversal
                    if components.pop().is_none() {
                        return None;
                    }
                }
                _ => components.push(part),
            }
        }

        Some(components.join("/"))
    }

    fn is_within_root(&self, path: &Path) -> bool {
        match (path.canonicalize(), self.root.canonicalize()) {
            (Ok(p), Ok(r)) => p.starts_with(&r),
            _ => false,
        }
    }

    fn contains_dot_file(&self, path: &str) -> bool {
        path.split('/').any(|part| part.starts_with('.') && part != ".")
    }

    fn guess_content_type(&self, path: &Path) -> String {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "html" | "htm" => "text/html; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "js" | "mjs" => "application/javascript; charset=utf-8",
            "json" => "application/json; charset=utf-8",
            "xml" => "application/xml; charset=utf-8",
            "txt" => "text/plain; charset=utf-8",
            "md" => "text/markdown; charset=utf-8",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "svg" => "image/svg+xml",
            "ico" => "image/x-icon",
            "webp" => "image/webp",
            "woff" => "font/woff",
            "woff2" => "font/woff2",
            "ttf" => "font/ttf",
            "otf" => "font/otf",
            "eot" => "application/vnd.ms-fontobject",
            "pdf" => "application/pdf",
            "zip" => "application/zip",
            "gz" | "gzip" => "application/gzip",
            "tar" => "application/x-tar",
            "mp3" => "audio/mpeg",
            "mp4" => "video/mp4",
            "webm" => "video/webm",
            "ogg" => "audio/ogg",
            "wav" => "audio/wav",
            "wasm" => "application/wasm",
            _ => "application/octet-stream",
        }
        .to_string()
    }

    fn needs_trailing_slash(&self, request_path: &str, resolved: &ResolvedFile) -> bool {
        self.config.canonical_uris
            && resolved.is_directory
            && !request_path.ends_with('/')
    }
}

/// File Server Plugin
pub struct FileServerPlugin {
    metadata: PluginMetadata,
    config: FileServerPluginConfig,
    state: Option<Arc<FileServerState>>,
    running: bool,
}

impl FileServerPlugin {
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("file_server", "0.1.0", PluginType::Handler)
            .with_description("Static file server with directory listing")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: false,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: FileServerPluginConfig::default(),
            state: None,
            running: false,
        }
    }

    pub fn get_hook(&self) -> Option<FileServerHook> {
        self.state.as_ref().map(|s| FileServerHook { state: s.clone() })
    }
}

impl Default for FileServerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for FileServerPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = FileServerPluginConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.state = Some(Arc::new(FileServerState::new(self.config.clone())?));
        self.running = true;
        tracing::info!(
            root = %self.config.root,
            browse = self.config.browse,
            "File server plugin started"
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.state = None;
        tracing::info!("File server plugin stopped");
        Ok(())
    }

    fn health_check(&self) -> bool {
        self.running && self.state.is_some()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// File server hook
pub struct FileServerHook {
    state: Arc<FileServerState>,
}

#[async_trait]
impl EarlyRequestHook for FileServerHook {
    fn priority(&self) -> HookPriority {
        HookPriority::LATE // File server should run after rewrites
    }

    async fn on_early_request(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        // Only handle GET and HEAD
        if request.method != "GET" && request.method != "HEAD" {
            return Ok(HookAction::Continue);
        }

        if let Some(resolved) = self.state.resolve_path(&request.path) {
            // Check if redirect needed for canonical URI
            if self.state.needs_trailing_slash(&request.path, &resolved) {
                let redirect_path = format!("{}/", request.path);
                ctx.set("redirect_location", redirect_path);
                ctx.set("redirect_status", 301u16);
                return Ok(HookAction::ShortCircuit);
            }

            // Store resolved file info
            ctx.set("resolved_file", resolved.clone());
            ctx.set("file_path", resolved.path.to_string_lossy().to_string());
            ctx.set("content_type", resolved.content_type.clone());
            ctx.set("is_directory", resolved.is_directory);

            if !resolved.is_directory {
                ctx.set("file_size", resolved.size);
                if let Some(modified) = resolved.modified {
                    ctx.set("file_modified", modified);
                }
            }

            tracing::debug!(
                path = %request.path,
                file = %resolved.path.display(),
                content_type = %resolved.content_type,
                "File resolved"
            );

            Ok(HookAction::ShortCircuit)
        } else {
            Ok(HookAction::Continue)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_plugin_creation() {
        let plugin = FileServerPlugin::new();
        assert_eq!(plugin.metadata().name, "file_server");
    }

    #[test]
    fn test_sanitize_path() {
        let config = FileServerPluginConfig::default();
        let state = FileServerState {
            config,
            root: PathBuf::from("/tmp"),
        };

        assert_eq!(state.sanitize_path("/foo/bar"), Some("foo/bar".to_string()));
        assert_eq!(state.sanitize_path("/./foo"), Some("foo".to_string()));
        assert_eq!(state.sanitize_path("/foo/../bar"), Some("bar".to_string()));
        assert_eq!(state.sanitize_path("/../../../etc/passwd"), None);
    }

    #[test]
    fn test_content_type_detection() {
        let config = FileServerPluginConfig::default();
        let state = FileServerState {
            config,
            root: PathBuf::from("/tmp"),
        };

        assert!(state.guess_content_type(Path::new("index.html")).contains("text/html"));
        assert!(state.guess_content_type(Path::new("style.css")).contains("text/css"));
        assert!(state.guess_content_type(Path::new("app.js")).contains("javascript"));
        assert!(state.guess_content_type(Path::new("image.png")).contains("image/png"));
    }

    #[test]
    fn test_resolve_path() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create test files
        fs::write(root.join("index.html"), "<html></html>").unwrap();
        fs::create_dir(root.join("subdir")).unwrap();
        fs::write(root.join("subdir/file.txt"), "content").unwrap();

        let config = FileServerPluginConfig {
            root: root.to_string_lossy().to_string(),
            ..Default::default()
        };
        let state = FileServerState::new(config).unwrap();

        // Test index file
        let resolved = state.resolve_path("/");
        assert!(resolved.is_some());
        let resolved = resolved.unwrap();
        assert!(!resolved.is_directory);
        assert!(resolved.content_type.contains("text/html"));

        // Test regular file
        let resolved = state.resolve_path("/subdir/file.txt");
        assert!(resolved.is_some());

        // Test non-existent file
        let resolved = state.resolve_path("/nonexistent");
        assert!(resolved.is_none());
    }

    #[test]
    fn test_dot_file_hiding() {
        let config = FileServerPluginConfig {
            hide_dot_files: true,
            ..Default::default()
        };
        let state = FileServerState {
            config,
            root: PathBuf::from("/tmp"),
        };

        assert!(state.contains_dot_file(".hidden"));
        assert!(state.contains_dot_file("dir/.hidden"));
        assert!(!state.contains_dot_file("normal"));
    }
}
