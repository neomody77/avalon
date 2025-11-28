//! Configuration file watcher for hot reload

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Configuration file watcher
pub struct ConfigWatcher {
    config_path: PathBuf,
    _watcher: RecommendedWatcher,
    rx: Receiver<Result<Event, notify::Error>>,
}

impl ConfigWatcher {
    /// Create a new configuration watcher
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, notify::Error> {
        let config_path = config_path.as_ref().to_path_buf();
        let (tx, rx) = channel();

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_secs(2)),
        )?;

        let watch_path = config_path.parent().unwrap_or_else(|| Path::new("."));
        watcher.watch(watch_path, RecursiveMode::NonRecursive)?;

        info!(path = ?config_path, "Configuration watcher started");

        Ok(Self {
            config_path,
            _watcher: watcher,
            rx,
        })
    }

    /// Poll for configuration changes (non-blocking)
    pub fn poll(&self) -> bool {
        let mut changed = false;

        while let Ok(result) = self.rx.try_recv() {
            match result {
                Ok(event) => {
                    if self.is_relevant_event(&event) {
                        debug!(event = ?event, "Configuration file event");
                        changed = true;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "File watcher error");
                }
            }
        }

        changed
    }

    /// Wait for configuration changes (blocking)
    pub fn wait_for_changes(&self) -> bool {
        loop {
            match self.rx.recv() {
                Ok(result) => match result {
                    Ok(event) => {
                        if self.is_relevant_event(&event) {
                            info!("Configuration file changed");
                            return true;
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "File watcher error");
                    }
                },
                Err(e) => {
                    error!(error = %e, "Channel receive error");
                    return false;
                }
            }
        }
    }

    fn is_relevant_event(&self, event: &Event) -> bool {
        use notify::EventKind;

        match event.kind {
            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_) => event
                .paths
                .iter()
                .any(|p| p == &self.config_path || p.file_name() == self.config_path.file_name()),
            _ => false,
        }
    }

    /// Get the configuration file path
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}

/// Configuration reload manager
pub struct ReloadManager {
    watcher: ConfigWatcher,
}

impl ReloadManager {
    /// Create a new reload manager
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, notify::Error> {
        let watcher = ConfigWatcher::new(config_path)?;
        Ok(Self { watcher })
    }

    /// Start the reload loop in a background task
    pub fn start<F>(self, callback: F) -> tokio::task::JoinHandle<()>
    where
        F: Fn(&Path) + Send + 'static,
    {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;

                if self.watcher.poll() {
                    info!("Configuration change detected, triggering reload");
                    callback(self.watcher.config_path());
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_watcher_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        fs::write(&config_path, "test").unwrap();

        let watcher = ConfigWatcher::new(&config_path);
        assert!(watcher.is_ok());
    }

    #[test]
    fn test_is_relevant_event() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        fs::write(&config_path, "test").unwrap();

        let watcher = ConfigWatcher::new(&config_path).unwrap();

        let event = Event {
            kind: notify::EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Any,
            )),
            paths: vec![config_path.clone()],
            attrs: Default::default(),
        };

        assert!(watcher.is_relevant_event(&event));

        let other_event = Event {
            kind: notify::EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Any,
            )),
            paths: vec![temp_dir.path().join("other.toml")],
            attrs: Default::default(),
        };

        assert!(!watcher.is_relevant_event(&other_event));
    }

    #[test]
    fn test_reload_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        fs::write(&config_path, "test").unwrap();

        let manager = ReloadManager::new(&config_path);
        assert!(manager.is_ok());
    }
}
