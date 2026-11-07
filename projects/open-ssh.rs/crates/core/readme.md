# open-ssh-core

Portable domain model for the OpenSSH application.

This crate owns the shared vocabulary that every consumer uses:

- the stable capability ids reported by `capabilities()`
- the three capability states (`unsupported_platform`, `not_implemented`,
  `dependency_blocked`) and the matching error codes
- the structured error shape carried across the native boundary
- the redacted audit fields written to `wae.audit/v0`
- the host platform descriptor

It contains no platform `cfg` branches and starts no process. The `ssh` module
implements the SSH transport in-process: packet framing, negotiation,
`curve25519-sha256` key exchange, host key verification, user authentication,
and the session channel. Only cryptographic primitives come from crates.

`exec` is available over `ssh`. Every other domain capability is registered as
`not_implemented` with a stable code so no caller can mistake an unimplemented
path for a successful one. Host keys are never trusted on first use: `exec`
requires an explicit `SHA256:` pin.

## Capability states

| State | Meaning |
|-------|---------|
| `None` | available |
| `unsupported_platform` | this host cannot provide the capability at all |
| `not_implemented` | registered in the product model, not implemented yet |
| `dependency_blocked` | a required dependency or admission gate is missing |

## Tests

```sh
cargo test -p open-ssh-core
```
