//! Audit trail at the N-API capability boundary.
//!
//! Every exported capability is recorded through [`run`], so the CLI and the GUI
//! cannot bypass attribution. The schema, sanitising, rotation, and query
//! implementation come from the shared `wae-audit` contract (`wae.audit/v0`).
//! This module supplies only the application name, version, and domain summary.

use std::sync::{Arc, PoisonError, RwLock};

use open_ssh_core::{Error as CoreError, ErrorCode, Result as CoreResult};
use serde_json::Value;
use wae::audit::{Actor, Auditor, Entry, Mode, Outcome, Query};

/// Application name written into every record.
const APP: &str = "open-ssh";

static AUDITOR: RwLock<Option<Arc<Auditor>>> = RwLock::new(None);

/// Target count and human-readable summary attached to a record.
#[derive(Debug, Clone)]
pub struct Summary {
    pub count: u64,
    pub summary: String,
}

impl Summary {
    pub fn new(count: u64, summary: impl Into<String>) -> Self {
        Self { count, summary: summary.into() }
    }
}

/// Process-wide auditor; built from environment defaults on first use.
fn auditor() -> Arc<Auditor> {
    if let Some(existing) = AUDITOR.read().unwrap_or_else(PoisonError::into_inner).as_ref() {
        return Arc::clone(existing);
    }
    let built = Arc::new(Auditor::from_env(APP, env!("CARGO_PKG_VERSION")));
    let mut guard = AUDITOR.write().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(guard.get_or_insert(built))
}

/// Replace the process-wide auditor after an explicit actor/session override.
pub fn configure(actor: Actor, session: Option<String>, host: Option<String>) {
    let mut builder = Auditor::builder(APP, env!("CARGO_PKG_VERSION")).actor(actor);
    if let Some(session) = session {
        builder = builder.session(session);
    }
    if let Some(host) = host {
        builder = builder.host(host);
    }
    let configured = Arc::new(builder.build());
    audit_configured(&configured);
    *AUDITOR.write().unwrap_or_else(PoisonError::into_inner) = Some(configured);
}

fn audit_configured(auditor: &Auditor) {
    let actor = auditor.actor();
    let params = serde_json::json!({
        "actorKind": actor.kind,
        "actorId": &actor.id,
        "actorSource": &actor.source,
        "session": auditor.session(),
        "host": auditor.host(),
    });
    let _ = run_with(auditor, "audit-configure", Mode::DryRun, params, || Ok(((), Summary::new(0, "audit configuration updated"))));
}

/// Record one capability call and return its result unchanged.
pub fn run<T>(capability: &str, mode: Mode, params: Value, body: impl FnOnce() -> CoreResult<(T, Summary)>) -> CoreResult<T> {
    let auditor = auditor();
    run_with(&auditor, capability, mode, params, body)
}

/// Record one capability call whose audit params only become complete after the
/// call, for example the remote exit status and captured byte counts.
pub fn run_metered<T>(capability: &str, mode: Mode, params: Value, body: impl FnOnce() -> CoreResult<(T, Value, Summary)>) -> CoreResult<T> {
    run_metered_with(&auditor(), capability, mode, params, body)
}

/// [`run_metered`] against an explicit auditor, used by tests.
pub fn run_metered_with<T>(
    auditor: &Auditor,
    capability: &str,
    mode: Mode,
    params: Value,
    body: impl FnOnce() -> CoreResult<(T, Value, Summary)>,
) -> CoreResult<T> {
    let call = auditor.call(capability, mode).params(params.clone());
    match body() {
        Ok((value, extra, summary)) => {
            let _ = call.params(merge(params, extra)).targets(summary.count, summary.summary).succeed();
            Ok(value)
        }
        Err(error) => {
            record_failure(call, &error);
            Err(error)
        }
    }
}

fn merge(mut base: Value, extra: Value) -> Value {
    if let (Value::Object(base), Value::Object(extra)) = (&mut base, extra) {
        base.extend(extra);
    }
    base
}

fn record_failure(call: wae::audit::Call<'_>, error: &CoreError) {
    let code = error.code().as_str();
    match error_outcome(error) {
        Outcome::Rejected => {
            let _ = call.reject(code);
        }
        _ => {
            let _ = call.fail(code);
        }
    }
}

/// [`run`] against an explicit auditor, used by tests.
pub fn run_with<T>(
    auditor: &Auditor,
    capability: &str,
    mode: Mode,
    params: Value,
    body: impl FnOnce() -> CoreResult<(T, Summary)>,
) -> CoreResult<T> {
    let call = auditor.call(capability, mode).params(params);
    match body() {
        Ok((value, summary)) => {
            let _ = call.targets(summary.count, summary.summary).succeed();
            Ok(value)
        }
        Err(error) => {
            let code = error.code().as_str();
            match error_outcome(&error) {
                Outcome::Rejected => {
                    let _ = call.reject(code);
                }
                _ => {
                    let _ = call.fail(code);
                }
            }
            Err(error)
        }
    }
}

/// Query the shared history.
pub fn query(filter: &Query) -> wae::audit::AuditResult<Vec<Entry>> {
    auditor().query(filter)
}

fn error_outcome(error: &CoreError) -> Outcome {
    if is_refusal(error.code()) { Outcome::Rejected } else { Outcome::Failure }
}

/// Whether an error code must be recorded as a refusal rather than a failure.
pub const fn is_refusal(code: ErrorCode) -> bool {
    matches!(code, ErrorCode::UnsupportedPlatform | ErrorCode::NotImplemented | ErrorCode::DependencyBlocked)
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use wae::audit::ActorKind;

    use open_ssh_core::CapabilityState;

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_auditor() -> (Auditor, PathBuf) {
        let dir = std::env::temp_dir().join(format!("open-ssh-audit-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
        let actor = Actor { kind: ActorKind::Agent, id: "agent-1".into(), source: "test".into() };
        let auditor = Auditor::builder(APP, "0.0.0").actor(actor).session("session-1").host("host-1").dir(dir.clone()).build();
        (auditor, dir)
    }

    #[test]
    fn success_is_recorded_with_targets() {
        let (auditor, dir) = test_auditor();
        run_with(&auditor, "capabilities", Mode::DryRun, serde_json::json!({ "limit": 5 }), || Ok((42, Summary::new(3, "three entries"))))
            .unwrap();
        let entries = auditor.query(&Query::default()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].capability, "capabilities");
        assert_eq!(entries[0].mode, Mode::DryRun);
        assert_eq!(entries[0].outcome, Outcome::Success);
        assert_eq!(entries[0].targets.count, 3);
        assert!(entries[0].error_code.is_none());
        let text = std::fs::read_to_string(dir.join("open-ssh.jsonl")).unwrap();
        assert!(text.contains("\"schema\":\"wae.audit/v0\""));
    }

    #[test]
    fn capability_refusals_are_rejected_with_a_stable_code() {
        let (auditor, _) = test_auditor();
        let rejected = run_with(&auditor, "session-open", Mode::Execute, Value::Null, || -> CoreResult<((), Summary)> {
            Err(CoreError::unavailable(CapabilityState::NotImplemented, "session-open", "skeleton"))
        });
        assert!(rejected.is_err());
        let entries = auditor.query(&Query::default()).unwrap();
        assert_eq!(entries[0].outcome, Outcome::Rejected);
        assert_eq!(entries[0].error_code.as_deref(), Some("not_implemented"));
    }

    #[test]
    fn measured_params_are_merged_before_write() {
        let (auditor, _) = test_auditor();
        run_metered_with(&auditor, "exec", Mode::Execute, serde_json::json!({ "hostHash": "abc", "commandBytes": 7 }), || {
            Ok((1, serde_json::json!({ "exitCode": 3, "stdoutBytes": 0 }), Summary::new(1, "one command")))
        })
        .unwrap();
        let entries = auditor.query(&Query::default()).unwrap();
        assert_eq!(entries[0].params["exitCode"], 3);
        assert_eq!(entries[0].params["stdoutBytes"], 0);
        assert_eq!(entries[0].params["hostHash"], "abc");
        assert_eq!(entries[0].params["commandBytes"], 7);
    }

    #[test]
    fn credentials_in_params_are_redacted_before_write() {
        let (auditor, dir) = test_auditor();
        run_with(&auditor, "capabilities", Mode::DryRun, serde_json::json!({ "token": "SECRET", "root": "C:/tmp" }), || {
            Ok(((), Summary::new(0, "none")))
        })
        .unwrap();
        let text = std::fs::read_to_string(dir.join("open-ssh.jsonl")).unwrap();
        assert!(!text.contains("SECRET"));
        assert!(text.contains("<redacted>"));
    }
}
