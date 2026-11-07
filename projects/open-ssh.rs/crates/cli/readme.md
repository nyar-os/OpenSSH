# open-ssh-cli

Contract library for the OpenSSH command line. This crate owns the values that
both the Rust native boundary and the TypeScript CLI must agree on:

- stable CLI command ids
- the `wae.cli-result/v0` machine-readable envelope
- the exit code table
- the `wae.cli-contract/v0` description returned by the native `cliContract()` export

It does not parse arguments, print text, or load the native addon. The single
product `bin` lives in `@wae/open-ssh-cli`.

## Exit codes

| Name | Code |
|------|------|
| `success` | 0 |
| `failure` | 1 |
| `usage` | 2 |
| `capability` | 3 |
| `canceled` | 4 |

Capability states `unsupported_platform`, `not_implemented`, and
`dependency_blocked` always map to `capability`.

## Tests

```sh
cargo test -p open-ssh-cli
```
