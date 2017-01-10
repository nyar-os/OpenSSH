#![deny(missing_debug_implementations, missing_copy_implementations)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![doc = include_str!("../readme.md")]

use open_ssh_core::{CapabilityState, audit::capability_ids, platform::capabilities};
use serde::Serialize;
use serde_json::Value;

/// Schema id of the CLI contract description.
pub const CONTRACT_SCHEMA: &str = "wae.cli-contract/v0";

/// Schema id of every machine-readable CLI result.
pub const ENVELOPE_SCHEMA: &str = "wae.cli-result/v0";

/// Stable CLI command ids.
pub mod command {
    /// Report the capability table.
    pub const CAPABILITIES: &str = "capabilities";
    /// Report product and native versions.
    pub const VERSION: &str = "version";
    /// Query local audit records.
    pub const AUDIT: &str = "audit";
    /// Host the WebView GUI.
    pub const GUI: &str = "gui";
}

/// Process exit codes. Capability states map to [`ExitCode::Capability`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// The call succeeded.
    Success,
    /// The call failed for a reason other than a capability state.
    Failure,
    /// The caller passed invalid arguments or an unknown command.
    Usage,
    /// The requested capability is unavailable.
    Capability,
    /// The user canceled the operation.
    Canceled,
}

impl ExitCode {
    /// Every exit code in stable order.
    pub const ALL: [Self; 5] = [Self::Success, Self::Failure, Self::Usage, Self::Capability, Self::Canceled];

    /// The numeric process exit code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Usage => 2,
            Self::Capability => 3,
            Self::Canceled => 4,
        }
    }

    /// The stable machine-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Usage => "usage",
            Self::Capability => "capability",
            Self::Canceled => "canceled",
        }
    }

    /// Map a stable error code to the exit code a CLI must return.
    pub fn for_error_code(code: &str) -> Self {
        match code {
            "unsupported_platform" | "not_implemented" | "dependency_blocked" => Self::Capability,
            "invalid_argument" | "unknown_command" => Self::Usage,
            _ => Self::Failure,
        }
    }
}

/// One row of the exit code table.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitCodeRow {
    /// Stable machine-readable name.
    pub name: &'static str,
    /// Numeric process exit code.
    pub code: u8,
}

/// One command exposed by the CLI.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandRow {
    /// CLI command token.
    pub id: &'static str,
    /// Capability this command resolves to.
    pub capability: &'static str,
    /// `meta` or `domain`.
    pub kind: &'static str,
    /// `null` when the command can run, otherwise the unavailable state.
    pub state: Option<CapabilityState>,
    /// Stable error code matching `state`.
    pub code: Option<&'static str>,
}

/// The full CLI contract returned by the native `cliContract()` export.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliContract {
    /// Schema id.
    pub schema: &'static str,
    /// Product name.
    pub app: &'static str,
    /// Envelope schema id used by every command.
    pub envelope: &'static str,
    /// Exit codes every consumer may observe.
    pub exit_codes: Vec<ExitCodeRow>,
    /// Commands, meta first and domain after.
    pub commands: Vec<CommandRow>,
}

/// An error payload inside the machine-readable envelope.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliError {
    /// Stable error code.
    pub code: String,
    /// Capability id when the error belongs to one.
    pub capability: Option<String>,
    /// Host platform descriptor such as `windows-x86_64`.
    pub platform: Option<String>,
    /// Human-readable message. Never contains credentials.
    pub message: String,
}

impl CliError {
    /// Build an error payload with only a code and message.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { code: code.into(), capability: None, platform: None, message: message.into() }
    }

    /// Attach a capability id.
    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capability = Some(capability.into());
        self
    }

    /// Attach a host platform descriptor.
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }
}

/// The `wae.cli-result/v0` envelope emitted by every command.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliResult {
    /// Envelope schema id.
    pub schema: &'static str,
    /// Whether the call succeeded.
    pub ok: bool,
    /// Successful payload. `null` when `ok` is false.
    pub data: Option<Value>,
    /// Failure payload. `null` when `ok` is true.
    pub error: Option<CliError>,
}

impl CliResult {
    /// Build a successful envelope.
    pub fn success(data: Value) -> Self {
        Self { schema: ENVELOPE_SCHEMA, ok: true, data: Some(data), error: None }
    }

    /// Build a failed envelope.
    pub fn failure(error: CliError) -> Self {
        Self { schema: ENVELOPE_SCHEMA, ok: false, data: None, error: Some(error) }
    }
}

/// Capabilities that the meta commands already expose. They must not be
/// repeated as domain commands.
const META_CAPABILITIES: [&str; 4] =
    [capability_ids::CAPABILITIES, capability_ids::VERSION, capability_ids::AUDIT_QUERY, capability_ids::AUDIT_CONFIGURE];

/// Build the CLI contract. Domain commands inherit the state of their capability row.
pub fn contract() -> CliContract {
    let report = capabilities();
    let mut commands = vec![
        CommandRow { id: command::CAPABILITIES, capability: capability_ids::CAPABILITIES, kind: "meta", state: None, code: None },
        CommandRow { id: command::VERSION, capability: capability_ids::VERSION, kind: "meta", state: None, code: None },
        CommandRow { id: command::AUDIT, capability: capability_ids::AUDIT_QUERY, kind: "meta", state: None, code: None },
        CommandRow { id: command::GUI, capability: "gui", kind: "meta", state: None, code: None },
    ];
    commands.extend(report.items.iter().filter(|item| !META_CAPABILITIES.contains(&item.id)).map(|item| CommandRow {
        id: item.id,
        capability: item.id,
        kind: "domain",
        state: item.state,
        code: item.code,
    }));
    CliContract {
        schema: CONTRACT_SCHEMA,
        app: report.app,
        envelope: ENVELOPE_SCHEMA,
        exit_codes: ExitCode::ALL.iter().map(|exit| ExitCodeRow { name: exit.name(), code: exit.code() }).collect(),
        commands,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::Failure.code(), 1);
        assert_eq!(ExitCode::Usage.code(), 2);
        assert_eq!(ExitCode::Capability.code(), 3);
        assert_eq!(ExitCode::Canceled.code(), 4);
    }

    #[test]
    fn capability_codes_map_to_the_capability_exit() {
        assert_eq!(ExitCode::for_error_code("unsupported_platform"), ExitCode::Capability);
        assert_eq!(ExitCode::for_error_code("not_implemented"), ExitCode::Capability);
        assert_eq!(ExitCode::for_error_code("dependency_blocked"), ExitCode::Capability);
        assert_eq!(ExitCode::for_error_code("invalid_argument"), ExitCode::Usage);
        assert_eq!(ExitCode::for_error_code("unknown_command"), ExitCode::Usage);
    }

    #[test]
    fn success_envelope_carries_the_schema() {
        let envelope = CliResult::success(serde_json::json!({ "ok": true }));
        let value = serde_json::to_value(&envelope).expect("envelope serializes");
        assert_eq!(value["schema"], ENVELOPE_SCHEMA);
        assert_eq!(value["ok"], true);
        assert_eq!(value["data"]["ok"], true);
        assert!(value["error"].is_null());
    }

    #[test]
    fn failure_envelope_carries_the_error() {
        let error = CliError::new("not_implemented", "skeleton round").with_capability("exec").with_platform("windows-x86_64");
        let value = serde_json::to_value(CliResult::failure(error)).expect("envelope serializes");
        assert_eq!(value["schema"], ENVELOPE_SCHEMA);
        assert_eq!(value["ok"], false);
        assert!(value["data"].is_null());
        assert_eq!(value["error"]["code"], "not_implemented");
        assert_eq!(value["error"]["capability"], "exec");
        assert_eq!(value["error"]["platform"], "windows-x86_64");
    }

    #[test]
    fn contract_lists_every_command_once() {
        let contract = contract();
        assert_eq!(contract.schema, CONTRACT_SCHEMA);
        assert_eq!(contract.app, "open-ssh");
        assert_eq!(contract.commands.len(), 15);
        let mut ids = Vec::new();
        for row in &contract.commands {
            assert!(!ids.contains(&row.id), "duplicate command id: {}", row.id);
            ids.push(row.id);
            match (row.kind, row.capability) {
                ("domain", capability_ids::EXEC) => {
                    assert_eq!(row.state, None, "`exec` must be exposed as available");
                    assert_eq!(row.code, None);
                }
                ("domain", _) => {
                    assert_eq!(row.state, Some(CapabilityState::NotImplemented));
                    assert_eq!(row.code, Some("not_implemented"));
                }
                (_, _) => {
                    assert_eq!(row.state, None);
                    assert_eq!(row.code, None);
                }
            }
        }
        assert_eq!(contract.exit_codes.len(), 5);
    }
}
