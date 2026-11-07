use serde::Serialize;

/// Stable capability ids shared by the native boundary, CLI, skills, and audit.
///
/// Capability ids describe a goal and never a protocol. The transport dimension
/// is reported separately in the capability matrix.
pub mod capability_ids {
    /// Report the capability table.
    pub const CAPABILITIES: &str = "capabilities";
    /// Report the product and native versions.
    pub const VERSION: &str = "version";
    /// Query local audit records.
    pub const AUDIT_QUERY: &str = "audit-query";
    /// Configure audit actor resolution.
    pub const AUDIT_CONFIGURE: &str = "audit-configure";
    /// Host the WebView GUI.
    pub const GUI: &str = "gui";

    /// Connect to a target and establish a session.
    pub const CONNECT: &str = "connect";
    /// Execute a command and return stdout, stderr, and the exit code.
    pub const EXEC: &str = "exec";
    /// Upload, download, and synchronize files.
    pub const TRANSFER: &str = "transfer";
    /// Enumerate sessions and report their state.
    pub const SESSION: &str = "session";

    /// Inventory and group managed hosts. Shared by every transport.
    pub const HOST_INVENTORY: &str = "host-inventory";
    /// Configure local, remote, and dynamic port forwarding.
    pub const PORT_FORWARD: &str = "port-forward";
    /// Generate, import, protect, and inspect host keys.
    pub const KEY_MANAGEMENT: &str = "key-management";
    /// Read, verify, and update `known_hosts` with explicit conflict handling.
    pub const KNOWN_HOSTS: &str = "known-hosts";
    /// Store credentials and passphrases in the Windows credential store.
    pub const CREDENTIAL_STORE: &str = "credential-store";

    /// Install the host integration and desktop entry.
    pub const HOST_INSTALL: &str = "host-install";
    /// Remove the host integration and clean residual state.
    pub const HOST_UNINSTALL: &str = "host-uninstall";
}

/// Audit fields recorded at the native boundary.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFields {
    /// Stable capability id.
    pub capability: String,
    /// Transport adapter used by the call.
    pub transport: String,
    /// Number of targets in the call.
    pub target_count: usize,
    /// Redacted target summary. Never contains credentials or private keys.
    pub target_summary: String,
}

impl AuditFields {
    /// Build redacted audit fields for one capability call.
    pub fn new(capability: impl Into<String>, transport: impl Into<String>, target_count: usize, target_summary: impl Into<String>) -> Self {
        Self { capability: capability.into(), transport: transport.into(), target_count, target_summary: target_summary.into() }
    }
}
