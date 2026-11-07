mod convert;
mod display;

use serde::Serialize;

/// The result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The only capability-level states a consumer may observe.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// The current host cannot provide this capability at all.
    UnsupportedPlatform,
    /// The capability exists in the product model but is not implemented yet.
    NotImplemented,
    /// A required dependency or admission gate is missing.
    DependencyBlocked,
}

impl CapabilityState {
    /// Stable machine-readable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::NotImplemented => "not_implemented",
            Self::DependencyBlocked => "dependency_blocked",
        }
    }

    /// Parse a stable code back into its state.
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "unsupported_platform" => Some(Self::UnsupportedPlatform),
            "not_implemented" => Some(Self::NotImplemented),
            "dependency_blocked" => Some(Self::DependencyBlocked),
            _ => None,
        }
    }
}

/// Stable error codes shared by the native boundary and the CLI.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    /// A capability is unavailable on the current platform.
    UnsupportedPlatform,
    /// A capability is registered but not implemented.
    NotImplemented,
    /// A required dependency is missing or not admitted.
    DependencyBlocked,
    /// The caller passed an invalid argument.
    InvalidArgument,
    /// An I/O operation failed.
    Io,
    /// An internal invariant failed.
    Internal,
}

impl ErrorCode {
    /// Stable machine-readable code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::NotImplemented => "not_implemented",
            Self::DependencyBlocked => "dependency_blocked",
            Self::InvalidArgument => "invalid_argument",
            Self::Io => "io_error",
            Self::Internal => "internal_error",
        }
    }

    /// Map a capability state to the matching error code.
    pub const fn from_state(state: CapabilityState) -> Self {
        match state {
            CapabilityState::UnsupportedPlatform => Self::UnsupportedPlatform,
            CapabilityState::NotImplemented => Self::NotImplemented,
            CapabilityState::DependencyBlocked => Self::DependencyBlocked,
        }
    }
}

/// A structured error crossing the native and CLI boundaries.
#[derive(Debug, Clone)]
pub struct Error {
    code: ErrorCode,
    capability: Option<String>,
    message: String,
}

impl Error {
    /// Build an error without a capability id.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, capability: None, message: message.into() }
    }

    /// Build an error bound to a stable capability id.
    pub fn for_capability(code: ErrorCode, capability: impl Into<String>, message: impl Into<String>) -> Self {
        Self { code, capability: Some(capability.into()), message: message.into() }
    }

    /// Build a capability-unavailable error from its state.
    pub fn unavailable(state: CapabilityState, capability: impl Into<String>, message: impl Into<String>) -> Self {
        Self::for_capability(ErrorCode::from_state(state), capability, message)
    }

    /// The stable error code.
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// The capability id, when the error belongs to one.
    pub fn capability(&self) -> Option<&str> {
        self.capability.as_deref()
    }

    /// The human-readable message. Never contains credentials.
    pub fn message(&self) -> &str {
        &self.message
    }
}
