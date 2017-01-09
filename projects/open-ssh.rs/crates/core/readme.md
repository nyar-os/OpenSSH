# open-ssh-core

Portable domain model for the OpenSSH application.

This crate owns the shared vocabulary that every consumer uses:

- the stable capability ids reported by `capabilities()`
- the three capability states (`unsupported_platform`, `not_implemented`,
  `dependency_blocked`) and the matching error codes
- the structured error shape carried across the native boundary
- the redacted audit fields written to `wae.audit/v0`
- the host platform descriptor

It contains no platform `cfg` branches, no I/O, no process spawning, and no
protocol implementation. The skeleton round registers every domain capability
as `not_implemented` with a stable code so no caller can mistake an unimplemented
path for a successful one.

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
