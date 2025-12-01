//! Plugin context for passing data through hooks

use bytes::Bytes;
use dashmap::DashMap;
use std::any::{Any, TypeId};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

/// Authentication identity
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    /// Subject identifier
    pub subject: String,
    /// Authentication method used
    pub method: String,
    /// Additional claims
    pub claims: std::collections::HashMap<String, String>,
}

/// Metadata visible to all plugins
#[derive(Debug, Default)]
pub struct ContextMetadata {
    /// Client IP address
    pub client_ip: Option<IpAddr>,
    /// Client socket address
    pub client_addr: Option<SocketAddr>,
    /// Authenticated identity (set by auth plugins)
    pub identity: Option<AuthIdentity>,
    /// Matched route name
    pub matched_route: Option<String>,
    /// Tags for conditional plugin execution
    pub tags: HashSet<String>,
    /// Request ID for tracing
    pub request_id: Option<String>,
}

/// Plugin context passed through the hook chain
pub struct PluginContext {
    /// Request start time
    pub request_start: Instant,
    /// Request metadata
    pub metadata: ContextMetadata,
    /// Host header value
    pub host: Option<String>,
    /// Request path
    pub path: String,
    /// HTTP method
    pub method: String,
    /// Whether the request is a WebSocket upgrade
    pub is_websocket: bool,
    /// Selected upstream address
    pub upstream: Option<String>,
    /// Response status code (set during response phase)
    pub response_status: Option<u16>,
    /// Response body buffer (for body hooks)
    pub response_body: Option<Bytes>,
    /// Plugin-specific data storage (type-erased)
    data: DashMap<(TypeId, String), Box<dyn Any + Send + Sync>>,
}

impl PluginContext {
    /// Create a new plugin context
    pub fn new(method: String, path: String) -> Self {
        Self {
            request_start: Instant::now(),
            metadata: ContextMetadata::default(),
            host: None,
            path,
            method,
            is_websocket: false,
            upstream: None,
            response_status: None,
            response_body: None,
            data: DashMap::new(),
        }
    }

    /// Store plugin-specific data with a key
    pub fn set<T: Any + Send + Sync + 'static>(&self, key: &str, value: T) {
        let type_id = TypeId::of::<T>();
        self.data.insert((type_id, key.to_string()), Box::new(value));
    }

    /// Retrieve plugin-specific data by key
    pub fn get<T: Any + Send + Sync + 'static>(&self, key: &str) -> Option<T>
    where
        T: Clone,
    {
        let type_id = TypeId::of::<T>();
        self.data
            .get(&(type_id, key.to_string()))
            .and_then(|v| v.downcast_ref::<T>().cloned())
    }

    /// Check if a key exists
    pub fn contains_key<T: Any + Send + Sync + 'static>(&self, key: &str) -> bool {
        let type_id = TypeId::of::<T>();
        self.data.contains_key(&(type_id, key.to_string()))
    }

    /// Remove plugin-specific data by key
    pub fn remove<T: Any + Send + Sync + 'static>(&self, key: &str) -> Option<T>
    where
        T: Clone,
    {
        let type_id = TypeId::of::<T>();
        self.data
            .remove(&(type_id, key.to_string()))
            .and_then(|(_, v)| v.downcast::<T>().ok().map(|b| *b))
    }

    /// Get elapsed time since request start
    pub fn elapsed(&self) -> std::time::Duration {
        self.request_start.elapsed()
    }

    /// Set client address
    pub fn set_client_addr(&mut self, addr: SocketAddr) {
        self.metadata.client_addr = Some(addr);
        self.metadata.client_ip = Some(addr.ip());
    }

    /// Add a tag
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.metadata.tags.insert(tag.into());
    }

    /// Check if a tag exists
    pub fn has_tag(&self, tag: &str) -> bool {
        self.metadata.tags.contains(tag)
    }

    /// Set the authenticated identity
    pub fn set_identity(&mut self, identity: AuthIdentity) {
        self.metadata.identity = Some(identity);
    }

    /// Check if the request is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.metadata.identity.is_some()
    }

    /// Get client IP as string
    pub fn client_ip_str(&self) -> Option<String> {
        self.metadata.client_ip.map(|ip| ip.to_string())
    }
}

impl Default for PluginContext {
    fn default() -> Self {
        Self::new(String::new(), String::new())
    }
}

/// Shared plugin context that can be safely passed across async boundaries
pub type SharedPluginContext = Arc<parking_lot::RwLock<PluginContext>>;

/// Create a shared plugin context
pub fn shared_context(ctx: PluginContext) -> SharedPluginContext {
    Arc::new(parking_lot::RwLock::new(ctx))
}
