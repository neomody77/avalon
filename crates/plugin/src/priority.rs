//! Hook priority system for controlling execution order

/// Priority level for hook execution (lower value = earlier execution)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HookPriority(pub i32);

impl HookPriority {
    /// First to execute (e.g., request logging start)
    pub const FIRST: HookPriority = HookPriority(-1000);

    /// Security-related hooks (rate limiting, auth, IP blocking)
    pub const SECURITY: HookPriority = HookPriority(-500);

    /// Early processing hooks
    pub const EARLY: HookPriority = HookPriority(-100);

    /// Normal priority (default)
    pub const NORMAL: HookPriority = HookPriority(0);

    /// Late processing hooks
    pub const LATE: HookPriority = HookPriority(100);

    /// Transform hooks (compression, rewriting)
    pub const TRANSFORM: HookPriority = HookPriority(500);

    /// Last to execute
    pub const LAST: HookPriority = HookPriority(1000);

    /// Create a custom priority
    pub fn custom(value: i32) -> Self {
        HookPriority(value)
    }
}

impl Default for HookPriority {
    fn default() -> Self {
        Self::NORMAL
    }
}

impl From<i32> for HookPriority {
    fn from(value: i32) -> Self {
        HookPriority(value)
    }
}
