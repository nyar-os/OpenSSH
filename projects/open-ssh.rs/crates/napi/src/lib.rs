//! Platform-neutral N-API surface for OpenSSH.
//!
//! This crate forwards generic capabilities to the `wae` facade and contains no
//! platform `cfg` branches and no platform string literals. Missing host
//! capabilities arrive as structured upstream errors. Audit is wrapped at every
//! capability boundary through the shared `wae.audit/v0` facility.
//!
//! The `exec` capability runs one command over an in-process SSH client. Every
//! other domain capability is still registered as `not_implemented` with a
//! stable code instead of fabricating a result.

#![deny(missing_docs)]

use std::{cell::RefCell, env, path::PathBuf, time::Duration};

use open_ssh_core::{
    CapabilityState, Error as CoreError, ErrorCode,
    audit::capability_ids,
    platform::{CapabilityItem, capabilities as core_capabilities, platform as core_platform},
    ssh::{self, ExecAuth, ExecRequest, ExecResult, Progress, TransferDirection, TransferRequest, TransferResult},
};
use serde_json::{Value, json};
use wae::{
    CallContext, Error, JsValue, Result, function, optional_string_prop, register_module,
    webview::{IpcHandler, IpcOutcome, OpenOptions, WebViewError, open},
};

mod audit;

use audit::Summary;
use wae::audit::Mode;

const APP_TITLE: &str = "OpenSSH";
const GUI_DIR_ENV: &str = "OPEN_SSH_GUI";

thread_local! {
    static GUI: RefCell<Option<wae::webview::WebViewHost>> = const { RefCell::new(None) };
}

struct HostIpc;

impl IpcHandler for HostIpc {
    fn on_ipc(&mut self, message: &str) -> IpcOutcome {
        let Ok(request) = serde_json::from_str::<Value>(message)
        else {
            return IpcOutcome::ReplyToPage(r#"{"ok":false,"error":"invalid json"}"#.to_string());
        };
        let kind = request.get("type").and_then(Value::as_str).unwrap_or_default();
        match kind {
            "close" => IpcOutcome::CloseWindow,
            "capabilities" => match audit::run(capability_ids::CAPABILITIES, Mode::Execute, Value::Null, || {
                Ok((capability_report(), Summary::new(1, "capabilities")))
            }) {
                Ok(report) => IpcOutcome::ReplyToPage(reply(json!({ "ok": true, "data": report }))),
                Err(error) => IpcOutcome::ReplyToPage(reply(json!({ "ok": false, "error": error_payload(&error) }))),
            },
            other => IpcOutcome::ReplyToPage(reply(json!({ "ok": false, "error": format!("unknown message: {other}") }))),
        }
    }
}

fn reply(value: Value) -> String {
    serde_json::to_string(&value).unwrap_or_else(|_| r#"{"ok":false,"error":"serialization failed"}"#.to_string())
}

/// The structured error shape shared by the native boundary and the CLI.
fn error_payload(error: &CoreError) -> Value {
    let platform = core_platform();
    json!({
        "code": error.code().as_str(),
        "capability": error.capability(),
        "platform": format!("{}-{}", platform.os, platform.arch),
        "message": error.message(),
    })
}

fn core_error(error: CoreError) -> Error {
    let text = match serde_json::to_string(&error_payload(&error)) {
        Ok(json) => format!("wae.error:{json}"),
        Err(_) => "wae.error:{\"code\":\"internal_error\",\"message\":\"error payload serialization failed\"}".to_string(),
    };
    // Capability errors are refusals, so the audit record uses `rejected` with the
    // capability state code instead of a generic execution failure.
    if audit::is_refusal(error.code()) { Error::new(text).refused(error.code().as_str()) } else { Error::new(text) }
}

/// Upstream host failure codes that mean a required GUI dependency is missing.
const GUI_DEPENDENCY_CODES: &[&str] = &["webview2_runtime_missing", "webkit_dependency_missing", "webkit_symbol_missing", "gtk_init_failed"];

fn webview_error(error: WebViewError) -> CoreError {
    match &error {
        WebViewError::Unsupported { capability, .. } => CoreError::unavailable(
            CapabilityState::UnsupportedPlatform,
            capability_ids::GUI,
            format!("upstream webview capability {capability:?} is unavailable on this target"),
        ),
        WebViewError::Host(failure) if GUI_DEPENDENCY_CODES.contains(&failure.code) => {
            CoreError::unavailable(CapabilityState::DependencyBlocked, capability_ids::GUI, error.to_string())
        }
        _ => CoreError::new(ErrorCode::Internal, error.to_string()),
    }
}

/// Capability report with the upstream facade row the domain cannot know about.
///
/// The `wae` facade only compiles on targets that carry a WebView backend, so `gui`
/// exists wherever this crate builds. Missing runtime libraries still surface from
/// `gui-open` as `dependency_blocked`, because the Linux backend resolves GTK at
/// runtime rather than at build time.
fn capability_report() -> open_ssh_core::platform::CapabilitiesReport {
    let mut report = core_capabilities();
    report.items.push(CapabilityItem {
        id: capability_ids::GUI,
        state: None,
        code: None,
        reason: "available",
        detail: "Host the WebView GUI over the same native capability boundary.",
        transports: Vec::new(),
    });
    let note = "`gui` covers `openGui`, `pumpEvents`, `closeGui` and `isGuiOpen`, missing runtime dependencies surface as `dependency_blocked` from `gui-open`";
    report.notes.push(note);
    report
}

/// Resolve a domain capability to its structured refusal.
///
/// Meta capabilities and available domain capabilities keep dedicated exports,
/// unknown ids and unknown transports are caller errors, and every remaining
/// domain capability is still `not_implemented`. When a transport is supplied, a
/// transport that does not carry the capability refuses with that transport's
/// own reason.
fn invoke_error(capability: &str, transport: Option<&str>) -> CoreError {
    let report = core_capabilities();
    let Some(item) = report.get(capability)
    else {
        return CoreError::new(ErrorCode::InvalidArgument, format!("unknown capability `{capability}`"));
    };
    if let Some(transport) = transport {
        let Some(row) = item.transport(transport)
        else {
            return CoreError::new(ErrorCode::InvalidArgument, format!("capability `{capability}` has no `{transport}` transport"));
        };
        if let Some(state) = row.state {
            return CoreError::unavailable(state, item.id, row.reason);
        }
    }
    if item.is_available() {
        return CoreError::new(ErrorCode::InvalidArgument, format!("`{capability}` is available through its dedicated export"));
    }
    CoreError::unavailable(item.state.unwrap_or(CapabilityState::NotImplemented), item.id, item.reason)
}

fn json_to_js(env: wae::Env, value: Value) -> Result<JsValue> {
    match value {
        Value::Null => env.null(),
        Value::Bool(value) => env.boolean(value),
        Value::Number(number) => match number.as_i64() {
            Some(value) => env.int64(value),
            None => env.double(number.as_f64().unwrap_or(0.0)),
        },
        Value::String(text) => env.string(&text),
        Value::Array(items) => {
            let array = env.array_with_length(items.len())?;
            for (index, item) in items.into_iter().enumerate() {
                array.set_element(index as u32, json_to_js(env, item)?)?;
            }
            Ok(array)
        }
        Value::Object(map) => {
            let object = env.object()?;
            for (key, item) in map {
                object.set_named(&key, json_to_js(env, item)?)?;
            }
            Ok(object)
        }
    }
}

fn value_to_js<T: serde::Serialize>(ctx: &CallContext, value: &T) -> Result<JsValue> {
    let json = serde_json::to_value(value).map_err(|error| Error::new(format!("serialize failed: {error}")))?;
    json_to_js(ctx.env(), json)
}

fn object_arg(ctx: &CallContext) -> Result<Option<JsValue>> {
    let Some(arg) = ctx.args().first().copied()
    else {
        return Ok(None);
    };
    if arg.is_undefined()? {
        return Ok(None);
    }
    Ok(Some(arg))
}

fn resolve_gui_dir(requested: Option<String>) -> Result<String> {
    if let Some(dir) = requested
        && !dir.trim().is_empty()
    {
        return Ok(dir);
    }
    if let Ok(dir) = env::var(GUI_DIR_ENV)
        && !dir.trim().is_empty()
    {
        return Ok(dir);
    }
    let candidates = [PathBuf::from("projects/open-ssh.ts/packages/open-ssh-cli/dist/gui"), PathBuf::from("dist/gui"), PathBuf::from("gui")];
    for candidate in candidates {
        if candidate.join("index.html").is_file() {
            return Ok(candidate.display().to_string());
        }
    }
    Err(Error::new("gui content dir not found: pass `contentDir` or build `projects/open-ssh.ts/packages/open-ssh-cli/dist/gui`"))
}

fn actor_kind(value: Option<&str>) -> wae::audit::ActorKind {
    match value {
        Some(value) if value.eq_ignore_ascii_case("agent") => wae::audit::ActorKind::Agent,
        _ => wae::audit::ActorKind::User,
    }
}

fn query_from_arg(arg: Option<JsValue>) -> Result<wae::audit::Query> {
    let mut query = wae::audit::Query::default();
    let Some(arg) = arg
    else {
        return Ok(query);
    };
    query.actor_kind = optional_string_prop(arg, "kind")?.map(|value| actor_kind(Some(value.as_str())));
    query.actor_id = optional_string_prop(arg, "id")?;
    query.capability = optional_string_prop(arg, "capability")?;
    query.from_ms = optional_i64(arg, "fromMs")?.map(|value| value.max(0) as u64);
    query.to_ms = optional_i64(arg, "toMs")?.map(|value| value.max(0) as u64);
    query.limit = optional_i64(arg, "limit")?.map(|value| value.max(0) as usize);
    Ok(query)
}

fn optional_i64(obj: JsValue, name: &str) -> Result<Option<i64>> {
    let value = obj.get_named(name)?;
    if value.is_undefined()? {
        return Ok(None);
    }
    Ok(Some(value.as_i64()?))
}

#[function]
fn version(ctx: CallContext) -> Result<JsValue> {
    let result = audit::run(capability_ids::VERSION, Mode::DryRun, Value::Null, || {
        Ok((env!("CARGO_PKG_VERSION").to_string(), Summary::new(0, "version")))
    });
    match result {
        Ok(version) => ctx.env().string(&version),
        Err(error) => Err(core_error(error)),
    }
}

#[function]
fn capabilities(ctx: CallContext) -> Result<JsValue> {
    let result = audit::run(capability_ids::CAPABILITIES, Mode::DryRun, Value::Null, || {
        let report = capability_report();
        let summary = Summary::new(report.items.len() as u64, "capabilities");
        Ok((report, summary))
    });
    match result {
        Ok(report) => value_to_js(&ctx, &report),
        Err(error) => Err(core_error(error)),
    }
}

/// Resolve one domain capability. The skeleton round always refuses with the
/// capability's stable unavailable code.
///
/// The optional second argument selects a transport. It is only used to pick a
/// more precise refusal and never changes which capabilities exist.
#[function]
fn invoke(ctx: CallContext) -> Result<JsValue> {
    let args = ctx.args();
    let capability = args.first().copied().ok_or_else(|| Error::new("invoke requires a capability id"))?.as_string()?;
    let transport = match args.get(1).copied() {
        Some(value) if !value.is_undefined()? => Some(value.as_string()?),
        _ => None,
    };
    let refusal = invoke_error(&capability, transport.as_deref());
    let params = json!({ "capability": &capability, "transport": transport });
    let result = audit::run(&capability, Mode::Execute, params, move || Err(refusal));
    match result {
        Ok(()) => Err(Error::new("invoke must not resolve in the skeleton round")),
        Err(error) => Err(core_error(error)),
    }
}

/// The stable CLI contract shared with the TypeScript CLI.
#[function(js_name = "cliContract")]
fn cli_contract(ctx: CallContext) -> Result<JsValue> {
    let contract = open_ssh_cli::contract();
    value_to_js(&ctx, &contract)
}

fn usage(message: impl Into<String>) -> Error {
    core_error(CoreError::new(ErrorCode::InvalidArgument, message.into()))
}

fn optional_bool_prop(obj: JsValue, name: &str) -> Result<Option<bool>> {
    let value = obj.get_named(name)?;
    if value.is_undefined()? {
        return Ok(None);
    }
    Ok(Some(value.as_bool()?))
}

fn required_string(obj: JsValue, name: &str) -> Result<String> {
    match optional_string_prop(obj, name)? {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(usage(format!("`{name}` is required"))),
    }
}

/// Connection and authentication fields shared by `exec` and `transfer`.
struct Endpoint {
    port: u16,
    timeout: Duration,
    auth: ExecAuth,
}

fn endpoint(obj: JsValue) -> Result<Endpoint> {
    let port = match optional_i64(obj, "port")? {
        Some(value) if (1..=65535).contains(&value) => value as u16,
        Some(_) => return Err(usage("`port` must be between 1 and 65535")),
        None => 22,
    };
    let timeout_ms = match optional_i64(obj, "timeoutMs")? {
        Some(value) if value > 0 => value as u64,
        Some(_) => return Err(usage("`timeoutMs` must be greater than zero")),
        None => 30_000,
    };
    let password = optional_string_prop(obj, "password")?;
    let identity_path = optional_string_prop(obj, "identityPath")?;
    let auth = match (password, identity_path) {
        (Some(password), None) if !password.is_empty() => ExecAuth::Password(password),
        (None, Some(path)) if !path.trim().is_empty() => ExecAuth::Identity(PathBuf::from(path)),
        (Some(_), Some(_)) => return Err(usage("pass either `password` or `identityPath`, never both")),
        _ => return Err(usage("this call requires `password` or `identityPath`")),
    };
    Ok(Endpoint { port, timeout: Duration::from_millis(timeout_ms), auth })
}

fn exec_request(arg: JsValue) -> Result<ExecRequest> {
    let transport = optional_string_prop(arg, "transport")?.unwrap_or_else(|| "ssh".to_string());
    let host = required_string(arg, "host")?;
    let user = required_string(arg, "user")?;
    let command = required_string(arg, "command")?;
    let host_key_sha256 = optional_string_prop(arg, "hostKeySha256")?.unwrap_or_default();
    let Endpoint { port, timeout, auth } = endpoint(arg)?;
    Ok(ExecRequest { transport, host, port, user, command, auth, host_key_sha256, timeout })
}

/// Run one command over the `ssh` transport.
///
/// Audit params carry the target and the auth method but never the command
/// body, the password, or the identity file contents.
#[function]
fn exec(ctx: CallContext) -> Result<JsValue> {
    let arg = object_arg(&ctx)?.ok_or_else(|| usage("exec requires an options object"))?;
    let request = exec_request(arg)?;
    let dry_run = optional_bool_prop(arg, "dryRun")?.unwrap_or(false);
    let params = json!({
        "transport": &request.transport,
        "hostHash": ssh::host_hash(&request.host),
        "port": request.port,
        "user": &request.user,
        "authMethod": request.auth.name(),
        "commandBytes": request.command.len(),
        "hostKeySha256": &request.host_key_sha256,
    });

    if dry_run {
        let result = audit::run(capability_ids::EXEC, Mode::DryRun, params, || {
            let preview = ssh::preview(&request)?;
            Ok((preview, Summary::new(1, format!("ssh exec preview for host {}", ssh::host_hash(&request.host)))))
        });
        return match result {
            Ok(preview) => value_to_js(&ctx, &preview),
            Err(error) => Err(core_error(error)),
        };
    }

    let summary_host = ssh::host_hash(&request.host);
    let port = request.port;
    let user = request.user.clone();
    let result = audit::run_metered(capability_ids::EXEC, Mode::Execute, params, move || {
        let outcome: ExecResult = ssh::execute(request)?;
        let extra = json!({
            "exitCode": outcome.exit_code,
            "stdoutBytes": outcome.stdout_bytes,
            "stderrBytes": outcome.stderr_bytes,
            "durationMs": outcome.duration_ms,
        });
        let summary = format!("ssh exec on host {summary_host}:{port} as {user}");
        Ok((outcome, extra, Summary::new(1, summary)))
    });
    match result {
        Ok(outcome) => value_to_js(&ctx, &outcome),
        Err(error) => Err(core_error(error)),
    }
}

fn transfer_request(arg: JsValue) -> Result<TransferRequest> {
    let transport = optional_string_prop(arg, "transport")?.unwrap_or_else(|| "ssh".to_string());
    let host = required_string(arg, "host")?;
    let user = required_string(arg, "user")?;
    let direction = match optional_string_prop(arg, "direction")?.as_deref() {
        Some("upload") => TransferDirection::Upload,
        Some("download") => TransferDirection::Download,
        Some("list") => TransferDirection::List,
        Some(other) => return Err(usage(format!("unknown `direction` `{other}`"))),
        None => return Err(usage("`direction` must be `upload`, `download`, or `list`")),
    };
    let remote_path = required_string(arg, "remotePath")?;
    let local_path = optional_string_prop(arg, "localPath")?.map(PathBuf::from);
    let resume = optional_bool_prop(arg, "resume")?.unwrap_or(false);
    let host_key_sha256 = optional_string_prop(arg, "hostKeySha256")?.unwrap_or_default();
    let Endpoint { port, timeout, auth } = endpoint(arg)?;
    Ok(TransferRequest { transport, host, port, user, auth, host_key_sha256, timeout, direction, local_path, remote_path, resume })
}

/// Upload, download, or list files over the `ssh` transport.
///
/// Audit params carry the direction, target, and auth method. They never carry
/// file contents, and the result adds the exact byte count, the resume offset,
/// and the wall-clock duration.
#[function]
fn transfer(ctx: CallContext) -> Result<JsValue> {
    let arg = object_arg(&ctx)?.ok_or_else(|| usage("transfer requires an options object"))?;
    let request = transfer_request(arg)?;
    let dry_run = optional_bool_prop(arg, "dryRun")?.unwrap_or(false);
    let show_progress = optional_bool_prop(arg, "progress")?.unwrap_or(false);
    let params = json!({
        "transport": &request.transport,
        "hostHash": ssh::host_hash(&request.host),
        "port": request.port,
        "user": &request.user,
        "authMethod": request.auth.name(),
        "hostKeySha256": &request.host_key_sha256,
        "direction": request.direction.name(),
        "resume": request.resume,
    });

    if dry_run {
        let result = audit::run(capability_ids::TRANSFER, Mode::DryRun, params, || {
            let preview = ssh::transfer_preview(&request)?;
            Ok((preview, Summary::new(1, format!("ssh transfer preview for host {}", ssh::host_hash(&request.host)))))
        });
        return match result {
            Ok(preview) => value_to_js(&ctx, &preview),
            Err(error) => Err(core_error(error)),
        };
    }

    let summary_host = ssh::host_hash(&request.host);
    let port = request.port;
    let user = request.user.clone();
    let direction = request.direction.name();
    let result = audit::run_metered(capability_ids::TRANSFER, Mode::Execute, params, move || {
        let mut bucket = u64::MAX;
        let outcome: TransferResult = ssh::transfer_with(request, |update| {
            if show_progress {
                report_progress(update, &mut bucket);
            }
        })?;
        let extra = json!({
            "bytes": outcome.bytes,
            "resumedFrom": outcome.resumed_from,
            "durationMs": outcome.duration_ms,
            "entries": outcome.entries.len(),
        });
        let summary = format!("ssh {direction} on host {summary_host}:{port} as {user}");
        Ok((outcome, extra, Summary::new(1, summary)))
    });
    match result {
        Ok(outcome) => value_to_js(&ctx, &outcome),
        Err(error) => Err(core_error(error)),
    }
}

/// Print human-readable progress to stderr in ten-percent steps.
fn report_progress(update: Progress, bucket: &mut u64) {
    let next = match update.total {
        Some(total) if total > 0 => update.transferred.saturating_mul(10) / total,
        _ => update.transferred / (1024 * 1024),
    };
    if next == *bucket {
        return;
    }
    *bucket = next;
    match update.total {
        Some(total) => eprintln!("transfer: {}% ({} of {} bytes)", next * 10, update.transferred, total),
        None => eprintln!("transfer: {} bytes", update.transferred),
    }
}

#[function(js_name = "openGui")]
fn open_gui(ctx: CallContext) -> Result<JsValue> {
    let arg = object_arg(&ctx)?;
    let content_dir = resolve_gui_dir(arg.and_then(|obj| optional_string_prop(obj, "contentDir").ok().flatten()))?;
    let title = arg.and_then(|obj| optional_string_prop(obj, "title").ok().flatten()).unwrap_or_else(|| APP_TITLE.to_string());
    let params = json!({ "contentDir": &content_dir, "title": &title });

    let result = audit::run(capability_ids::GUI, Mode::Execute, params, || {
        let options = OpenOptions::from_content_dir(&content_dir, &title);
        let host = open(options, Box::new(HostIpc)).map_err(webview_error)?;
        let backend = host.backend_name().to_string();
        GUI.with(|slot| {
            *slot.borrow_mut() = Some(host);
        });
        Ok((backend, Summary::new(1, "gui window opened")))
    });
    match result {
        Ok(backend) => {
            let object = ctx.env().object()?;
            object.set_named("backend", ctx.env().string(&backend)?)?;
            Ok(object)
        }
        Err(error) => Err(core_error(error)),
    }
}

#[function(js_name = "pumpEvents")]
fn pump_events(ctx: CallContext) -> Result<JsValue> {
    let result = audit::run(capability_ids::GUI, Mode::Execute, Value::Null, || {
        let alive = GUI.with(|slot| slot.borrow_mut().as_mut().map(|host| host.pump()).unwrap_or(false));
        Ok((alive, Summary::new(1, "gui event pump")))
    });
    match result {
        Ok(alive) => ctx.env().boolean(alive),
        Err(error) => Err(core_error(error)),
    }
}

#[function(js_name = "closeGui")]
fn close_gui(ctx: CallContext) -> Result<JsValue> {
    let result = audit::run(capability_ids::GUI, Mode::Execute, Value::Null, || {
        let closed = GUI.with(|slot| {
            let mut slot = slot.borrow_mut();
            match slot.as_mut() {
                Some(host) => host.close().is_ok(),
                None => false,
            }
        });
        if closed {
            GUI.with(|slot| {
                slot.borrow_mut().take();
            });
        }
        Ok((closed, Summary::new(1, "gui window close")))
    });
    match result {
        Ok(closed) => ctx.env().boolean(closed),
        Err(error) => Err(core_error(error)),
    }
}

#[function(js_name = "isGuiOpen")]
fn is_gui_open(ctx: CallContext) -> Result<JsValue> {
    let result = audit::run(capability_ids::GUI, Mode::DryRun, Value::Null, || {
        let alive = GUI.with(|slot| slot.borrow().as_ref().map(|host| host.is_alive()).unwrap_or(false));
        Ok((alive, Summary::new(1, "gui status")))
    });
    match result {
        Ok(alive) => ctx.env().boolean(alive),
        Err(error) => Err(core_error(error)),
    }
}

#[function(js_name = "configureAudit")]
fn configure_audit(ctx: CallContext) -> Result<JsValue> {
    let arg = object_arg(&ctx)?;
    let actor = wae::audit::Actor {
        kind: actor_kind(arg.and_then(|obj| optional_string_prop(obj, "actorKind").ok().flatten()).as_deref()),
        id: arg.and_then(|obj| optional_string_prop(obj, "actorId").ok().flatten()).unwrap_or_else(|| "unknown".to_string()),
        source: arg.and_then(|obj| optional_string_prop(obj, "actorSource").ok().flatten()).unwrap_or_else(|| "local".to_string()),
    };
    let session = arg.and_then(|obj| optional_string_prop(obj, "session").ok().flatten());
    let host = arg.and_then(|obj| optional_string_prop(obj, "host").ok().flatten());
    audit::configure(actor, session, host);
    let object = ctx.env().object()?;
    object.set_named("ok", ctx.env().boolean(true)?)?;
    Ok(object)
}

#[function(js_name = "auditQuery")]
fn audit_query(ctx: CallContext) -> Result<JsValue> {
    let filter = query_from_arg(ctx.args().first().copied())?;
    let params = json!({ "capability": filter.capability, "limit": filter.limit });
    let result = audit::run(capability_ids::AUDIT_QUERY, Mode::DryRun, params, || {
        let entries = audit::query(&filter).map_err(|error| CoreError::new(ErrorCode::Internal, error.to_string()))?;
        let summary = Summary::new(entries.len() as u64, "audit query");
        Ok((entries, summary))
    });
    match result {
        Ok(entries) => {
            let json = serde_json::to_string(&entries).map_err(|error| Error::new(error.to_string()))?;
            ctx.env().string(&json)
        }
        Err(error) => Err(core_error(error)),
    }
}

register_module![
    version,
    capabilities,
    exec,
    transfer,
    invoke,
    cli_contract,
    open_gui,
    pump_events,
    close_gui,
    is_gui_open,
    configure_audit,
    audit_query
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_gui_runtime_dependencies_map_to_dependency_blocked() {
        for code in GUI_DEPENDENCY_CODES {
            let mapped = webview_error(WebViewError::host(code, "load_libraries", "missing dependency"));
            assert_eq!(mapped.code(), ErrorCode::DependencyBlocked);
            assert_eq!(mapped.capability(), Some(capability_ids::GUI));
        }
    }

    #[test]
    fn other_host_failures_stay_plain_domain_errors() {
        let mapped = webview_error(WebViewError::host("create_window_failed", "create_window", "boom"));
        assert_eq!(mapped.code(), ErrorCode::Internal);
    }

    #[test]
    fn capability_report_lists_gui_and_reasons_for_unavailable_rows() {
        let report = capability_report();
        let gui = report.get(capability_ids::GUI).expect("gui row");
        assert!(gui.is_available());
        assert!(gui.transports.is_empty());
        assert!(report.notes.iter().any(|note| note.contains("dependency_blocked")));
        assert!(report.get(capability_ids::EXEC).expect("exec row").is_available());
        assert!(report.get(capability_ids::TRANSFER).expect("transfer row").is_available());
        for id in [capability_ids::HOST_INSTALL, capability_ids::HOST_UNINSTALL, capability_ids::PORT_FORWARD] {
            let item = report.get(id).unwrap_or_else(|| panic!("missing capability row: {id}"));
            assert!(!item.is_available());
            assert!(!item.reason.is_empty());
            assert!(!item.detail.is_empty());
        }
    }

    #[test]
    fn invoke_refuses_every_unavailable_domain_capability_with_its_stable_code() {
        for id in [capability_ids::CONNECT, capability_ids::SESSION, capability_ids::HOST_INVENTORY] {
            let error = invoke_error(id, None);
            assert_eq!(error.code(), ErrorCode::NotImplemented);
            assert_eq!(error.capability(), Some(id));
        }
    }

    #[test]
    fn invoke_points_available_capabilities_at_their_export() {
        for id in [capability_ids::EXEC, capability_ids::TRANSFER] {
            let error = invoke_error(id, None);
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
            assert!(error.message().contains("dedicated export"), "`{id}` must point at its dedicated export");
        }
    }

    #[test]
    fn invoke_explains_the_transport_refusal() {
        let error = invoke_error(capability_ids::EXEC, Some("rdp"));
        assert_eq!(error.code(), ErrorCode::NotImplemented);
        assert_eq!(error.capability(), Some(capability_ids::EXEC));
        assert!(error.message().contains("command channel"));

        let unsupported = invoke_error(capability_ids::PORT_FORWARD, Some("rdp"));
        assert_eq!(unsupported.code(), ErrorCode::NotImplemented);
        assert_eq!(unsupported.capability(), Some(capability_ids::PORT_FORWARD));
    }

    #[test]
    fn invoke_rejects_unknown_capabilities_transports_and_meta_rows_as_usage_errors() {
        assert_eq!(invoke_error("not-a-capability", None).code(), ErrorCode::InvalidArgument);
        assert_eq!(invoke_error(capability_ids::CAPABILITIES, None).code(), ErrorCode::InvalidArgument);
        assert!(invoke_error(capability_ids::CAPABILITIES, None).capability().is_none());
        assert_eq!(invoke_error(capability_ids::EXEC, Some("vnc")).code(), ErrorCode::InvalidArgument);
        assert_eq!(invoke_error(capability_ids::CAPABILITIES, Some("ssh")).code(), ErrorCode::InvalidArgument);
    }
}
