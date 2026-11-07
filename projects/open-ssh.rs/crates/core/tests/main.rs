use open_ssh_core::{
    CapabilityState, Error, ErrorCode,
    audit::{AuditFields, capability_ids},
    platform::{TRANSPORTS, capabilities, platform},
};

const DOMAIN: [&str; 11] = [
    capability_ids::CONNECT,
    capability_ids::EXEC,
    capability_ids::TRANSFER,
    capability_ids::SESSION,
    capability_ids::HOST_INVENTORY,
    capability_ids::PORT_FORWARD,
    capability_ids::KEY_MANAGEMENT,
    capability_ids::KNOWN_HOSTS,
    capability_ids::CREDENTIAL_STORE,
    capability_ids::HOST_INSTALL,
    capability_ids::HOST_UNINSTALL,
];

const META: [&str; 4] = [capability_ids::CAPABILITIES, capability_ids::VERSION, capability_ids::AUDIT_QUERY, capability_ids::AUDIT_CONFIGURE];

#[test]
fn every_domain_capability_is_registered_as_not_implemented() {
    let report = capabilities();
    for id in DOMAIN {
        let item = report.get(id).unwrap_or_else(|| panic!("missing capability row: {id}"));
        assert_eq!(item.state, Some(CapabilityState::NotImplemented), "{id} must stay not_implemented");
        assert_eq!(item.code, Some("not_implemented"), "{id} must carry the stable code");
        assert!(!item.is_available(), "{id} must not report as available");
        assert!(!item.reason.is_empty(), "{id} must explain why it is unavailable");
        assert!(!item.detail.is_empty(), "{id} must describe the target behaviour");
    }
}

#[test]
fn capability_ids_never_encode_a_transport() {
    for id in DOMAIN {
        let lowered = id.to_ascii_lowercase();
        assert!(!lowered.contains("ssh"), "{id} must not encode a transport name");
        assert!(!lowered.contains("rdp"), "{id} must not encode a transport name");
        assert!(!lowered.contains("sftp"), "{id} must not encode a transport name");
    }
}

#[test]
fn both_transports_are_registered_once() {
    let report = capabilities();
    assert_eq!(report.transports, TRANSPORTS.to_vec());
    for id in [capability_ids::CONNECT, capability_ids::EXEC, capability_ids::TRANSFER, capability_ids::SESSION] {
        let item = report.get(id).unwrap_or_else(|| panic!("missing capability row: {id}"));
        assert_eq!(item.transports.len(), TRANSPORTS.len(), "{id} must report both transports");
        for transport in TRANSPORTS {
            assert!(item.transport(transport).is_some(), "{id} is missing the `{transport}` row");
        }
    }
}

#[test]
fn rdp_reports_no_exec_and_ssh_does() {
    let report = capabilities();
    let exec = report.get(capability_ids::EXEC).expect("exec row");
    let rdp = exec.transport("rdp").expect("rdp exec row");
    assert!(!rdp.supports(), "rdp must not support exec");
    assert_eq!(rdp.state, Some(CapabilityState::NotImplemented));
    assert_eq!(rdp.code, Some("not_implemented"));
    assert!(rdp.reason.contains("command channel"), "rdp must explain the missing command channel");
    let ssh = exec.transport("ssh").expect("ssh exec row");
    assert!(ssh.supports(), "ssh must support exec");
}

#[test]
fn connect_transfer_and_session_are_supported_by_both_transports() {
    let report = capabilities();
    for id in [capability_ids::CONNECT, capability_ids::TRANSFER, capability_ids::SESSION] {
        let item = report.get(id).unwrap_or_else(|| panic!("missing capability row: {id}"));
        for transport in TRANSPORTS {
            let row = item.transport(transport).unwrap_or_else(|| panic!("{id} is missing `{transport}`"));
            assert!(row.supports(), "{id} must be supported over `{transport}`");
        }
    }
}

#[test]
fn rdp_only_transports_have_their_own_refusal_text() {
    let report = capabilities();
    for id in [capability_ids::PORT_FORWARD, capability_ids::KEY_MANAGEMENT, capability_ids::KNOWN_HOSTS] {
        let item = report.get(id).unwrap_or_else(|| panic!("missing capability row: {id}"));
        let rdp = item.transport("rdp").unwrap_or_else(|| panic!("{id} is missing the rdp row"));
        assert!(!rdp.supports(), "{id} must not claim rdp support");
        assert!(!rdp.reason.is_empty(), "{id} must explain the rdp refusal");
    }
}

#[test]
fn meta_capabilities_are_available_and_transport_neutral() {
    let report = capabilities();
    for id in META {
        let item = report.get(id).unwrap_or_else(|| panic!("missing capability row: {id}"));
        assert!(item.is_available(), "{id} must be available in the skeleton round");
        assert_eq!(item.state, None);
        assert_eq!(item.code, None);
        assert!(item.transports.is_empty(), "{id} must not report transports");
    }
}

#[test]
fn capability_ids_are_unique() {
    let report = capabilities();
    let mut seen = Vec::with_capacity(report.items.len());
    for item in &report.items {
        assert!(!seen.contains(&item.id), "duplicate capability id: {}", item.id);
        seen.push(item.id);
    }
    assert_eq!(report.app, "open-ssh");
    assert_eq!(report.items.len(), DOMAIN.len() + META.len());
}

#[test]
fn capability_state_codes_round_trip() {
    for state in [CapabilityState::UnsupportedPlatform, CapabilityState::NotImplemented, CapabilityState::DependencyBlocked] {
        assert_eq!(CapabilityState::from_code(state.code()), Some(state));
    }
    assert_eq!(CapabilityState::from_code("available"), None);
    assert_eq!(ErrorCode::from_state(CapabilityState::NotImplemented).as_str(), "not_implemented");
    assert_eq!(ErrorCode::InvalidArgument.as_str(), "invalid_argument");
    assert_eq!(ErrorCode::Io.as_str(), "io_error");
}

#[test]
fn unavailable_errors_expose_the_capability_and_code() {
    let error = Error::unavailable(CapabilityState::NotImplemented, capability_ids::EXEC, "skeleton round");
    assert_eq!(error.code(), ErrorCode::NotImplemented);
    assert_eq!(error.capability(), Some(capability_ids::EXEC));
    assert_eq!(error.message(), "skeleton round");
    assert_eq!(error.to_string(), "not_implemented (exec): skeleton round");
}

#[test]
fn audit_fields_carry_the_transport_separately() {
    let fields = AuditFields::new(capability_ids::TRANSFER, "rdp", 2, "host aliases only");
    let value = serde_json::to_value(&fields).expect("audit fields serialize");
    assert_eq!(value["capability"], capability_ids::TRANSFER);
    assert_eq!(value["transport"], "rdp");
    assert_eq!(value["targetCount"], 2);
    assert_eq!(value["targetSummary"], "host aliases only");
}

#[test]
fn platform_reports_the_build_host() {
    let info = platform();
    assert!(!info.os.is_empty());
    assert!(!info.arch.is_empty());
}
