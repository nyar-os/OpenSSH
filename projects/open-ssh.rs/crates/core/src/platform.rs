use crate::{audit::capability_ids, errors::CapabilityState};
use serde::Serialize;

/// The host platform reported by the native crate.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformInfo {
    /// Operating system constant such as `windows`.
    pub os: &'static str,
    /// Architecture constant such as `x86_64`.
    pub arch: &'static str,
}

/// Transport adapters known to the product.
pub const TRANSPORTS: [&str; 2] = ["ssh", "rdp"];

/// How one transport adapter relates to a capability.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportRow {
    /// Transport adapter name such as `ssh` or `rdp`.
    pub transport: &'static str,
    /// `null` when this transport supports the capability, otherwise the state.
    pub state: Option<CapabilityState>,
    /// Stable code matching `state`.
    pub code: Option<&'static str>,
    /// Why the transport does not support the capability.
    pub reason: &'static str,
}

impl TransportRow {
    /// Whether this transport supports the capability.
    pub const fn supports(&self) -> bool {
        self.state.is_none()
    }
}

/// One row in the capability matrix.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityItem {
    /// Stable capability id.
    pub id: &'static str,
    /// `null` when any transport can invoke it, otherwise one of the three states.
    pub state: Option<CapabilityState>,
    /// Stable error code matching `state`. `null` when available.
    pub code: Option<&'static str>,
    /// Why the capability is unavailable.
    pub reason: &'static str,
    /// What the capability does once implemented.
    pub detail: &'static str,
    /// Per-transport support. Empty for transport-neutral capabilities.
    pub transports: Vec<TransportRow>,
}

impl CapabilityItem {
    /// Whether the capability can be invoked on this host right now.
    pub const fn is_available(&self) -> bool {
        self.state.is_none()
    }

    /// The transport row for `transport`, when registered.
    pub fn transport(&self, transport: &str) -> Option<&TransportRow> {
        self.transports.iter().find(|row| row.transport == transport)
    }
}

/// The full capability report returned to CLI, GUI, and agents.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesReport {
    /// Product name.
    pub app: &'static str,
    /// Operating system constant such as `windows`.
    pub platform: &'static str,
    /// CPU architecture constant such as `x86_64`.
    pub arch: &'static str,
    /// Native package version.
    pub version: &'static str,
    /// Transport adapters known to the product.
    pub transports: Vec<&'static str>,
    /// Every registered capability, including unavailable rows.
    pub items: Vec<CapabilityItem>,
    /// Contract notes that apply to the whole table.
    pub notes: Vec<&'static str>,
}

impl CapabilitiesReport {
    /// Look up a capability row by its stable id.
    pub fn get(&self, id: &str) -> Option<&CapabilityItem> {
        self.items.iter().find(|item| item.id == id)
    }
}

const SKELETON_REASON: &str = "The skeleton round registers the capability but does not implement it.";

type TransportSpec = (&'static str, Option<CapabilityState>, &'static str);

const SUPPORTS: Option<CapabilityState> = None;
const NO_EXEC: Option<CapabilityState> = Some(CapabilityState::NotImplemented);
const NO_PORT_FORWARD: Option<CapabilityState> = Some(CapabilityState::NotImplemented);
const NO_KEYS: Option<CapabilityState> = Some(CapabilityState::NotImplemented);
const NO_KNOWN_HOSTS: Option<CapabilityState> = Some(CapabilityState::NotImplemented);

const CONNECT_TRANSPORTS: &[TransportSpec] = &[("ssh", SUPPORTS, "planned"), ("rdp", SUPPORTS, "planned")];
const EXEC_TRANSPORTS: &[TransportSpec] = &[
    ("ssh", SUPPORTS, "planned"),
    ("rdp", NO_EXEC, "RDP has no command channel. The protocol carries graphics, input, clipboard, and redirection channels only."),
];
const TRANSFER_TRANSPORTS: &[TransportSpec] = &[("ssh", SUPPORTS, "SFTP"), ("rdp", SUPPORTS, "drive redirection")];
const SESSION_TRANSPORTS: &[TransportSpec] = &[("ssh", SUPPORTS, "planned"), ("rdp", SUPPORTS, "planned")];
const HOST_TRANSPORTS: &[TransportSpec] = &[("ssh", SUPPORTS, "planned"), ("rdp", SUPPORTS, "planned")];
const PORT_FORWARD_TRANSPORTS: &[TransportSpec] =
    &[("ssh", SUPPORTS, "planned"), ("rdp", NO_PORT_FORWARD, "RDP has no equivalent port forwarding.")];
const KEY_TRANSPORTS: &[TransportSpec] =
    &[("ssh", SUPPORTS, "planned"), ("rdp", NO_KEYS, "RDP has no host key concept. It relies on TLS certificate verification instead.")];
const KNOWN_HOSTS_TRANSPORTS: &[TransportSpec] =
    &[("ssh", SUPPORTS, "planned"), ("rdp", NO_KNOWN_HOSTS, "RDP uses a server certificate fingerprint check, not `known_hosts`.")];

const DOMAIN: &[(&str, &[TransportSpec], &str)] = &[
    (capability_ids::CONNECT, CONNECT_TRANSPORTS, "Connect to a target and establish a session over the selected transport."),
    (capability_ids::EXEC, EXEC_TRANSPORTS, "Execute a command and return stdout, stderr, and the exit code."),
    (capability_ids::TRANSFER, TRANSFER_TRANSPORTS, "Upload, download, and synchronize files with a dry-run plan."),
    (capability_ids::SESSION, SESSION_TRANSPORTS, "Enumerate sessions and report their state and disconnect codes."),
    (capability_ids::HOST_INVENTORY, HOST_TRANSPORTS, "Inventory and group managed hosts for every transport."),
    (capability_ids::PORT_FORWARD, PORT_FORWARD_TRANSPORTS, "Configure local, remote, and dynamic port forwarding."),
    (capability_ids::KEY_MANAGEMENT, KEY_TRANSPORTS, "Generate, import, protect, and inspect host keys."),
    (capability_ids::KNOWN_HOSTS, KNOWN_HOSTS_TRANSPORTS, "Verify host keys and update `known_hosts` with explicit conflict handling."),
    (capability_ids::CREDENTIAL_STORE, HOST_TRANSPORTS, "Store credentials and passphrases in the Windows credential store."),
    (capability_ids::HOST_INSTALL, HOST_TRANSPORTS, "Install the host integration and desktop entry."),
    (capability_ids::HOST_UNINSTALL, HOST_TRANSPORTS, "Remove the host integration and clean residual state."),
];

const META: &[(&str, &str)] = &[
    (capability_ids::CAPABILITIES, "Report the capability matrix."),
    (capability_ids::VERSION, "Report product and native versions."),
    (capability_ids::AUDIT_QUERY, "Query local audit records."),
    (capability_ids::AUDIT_CONFIGURE, "Resolve and configure the audit actor."),
];

/// Current host platform.
pub const fn platform() -> PlatformInfo {
    PlatformInfo { os: std::env::consts::OS, arch: std::env::consts::ARCH }
}

/// Build the capability report. Domain rows stay unavailable in the skeleton round.
pub fn capabilities() -> CapabilitiesReport {
    let mut items = Vec::with_capacity(DOMAIN.len() + META.len());
    for (id, detail) in META {
        items.push(CapabilityItem { id, state: None, code: None, reason: "available", detail, transports: Vec::new() });
    }
    for (id, transports, detail) in DOMAIN {
        items.push(CapabilityItem {
            id,
            state: Some(CapabilityState::NotImplemented),
            code: Some("not_implemented"),
            reason: SKELETON_REASON,
            detail,
            transports: transports
                .iter()
                .map(|(transport, state, reason)| TransportRow { transport, state: *state, code: state.map(CapabilityState::code), reason })
                .collect(),
        });
    }
    CapabilitiesReport {
        app: "open-ssh",
        platform: platform().os,
        arch: platform().arch,
        version: env!("CARGO_PKG_VERSION"),
        transports: TRANSPORTS.to_vec(),
        items,
        notes: vec![
            "Domain capabilities are intentionally not_implemented in this skeleton round.",
            "Capability, version, audit, and GUI meta capabilities are available.",
            "Capability ids describe a goal. Transport support is reported per row and never encoded in the id.",
            "RDP supports connect, session, and transfer only. It has no command channel, so `exec` is not_implemented for rdp.",
            "No capability may fall back to an external ssh, sftp, scp, mstsc, or winrs process.",
        ],
    }
}
