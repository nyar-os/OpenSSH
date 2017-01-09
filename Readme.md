# OpenSSH

Transport-aware remote host manager. Capabilities are defined by the goal
(`connect`, `exec`, `transfer`, `session`), and protocol adapters are a separate
dimension. In this skeleton round every domain capability refuses with
`not_implemented`, and no external `ssh`, `sftp`, `scp`, `mstsc`, or `winrs`
process is ever started.

## Transports

| Transport | connect | exec | transfer | session |
|-----------|---------|------|----------|---------|
| `ssh` | supported | supported | SFTP | supported |
| `rdp` | supported | not available | drive redirection | supported |

RDP has no command channel, so `exec` over RDP is not available and stays
`not_implemented`. The product does not guarantee that one port offers both
connection and command execution. Availability depends on the transport.

## Layout

| Path | Responsibility |
|------|----------------|
| `projects/open-ssh.rs/crates/core` | Portable domain model, capability matrix, transport rows, audit fields |
| `projects/open-ssh.rs/crates/napi` | Platform-neutral N-API surface over the `wae` facade |
| `projects/open-ssh.rs/crates/cli` | Command ids, exit codes, and the machine-readable contract |
| `projects/open-ssh.ts/packages/open-ssh` | Typed library over the native boundary. Owns no `bin` |
| `projects/open-ssh.ts/packages/open-ssh-cli` | The `open-ssh` command entry and locales |
| `projects/open-ssh.ts/packages/open-ssh-ui` | VMZ page and design tokens. Staged into the CLI `dist/gui` |
| `projects/open-ssh.ts/packages/open-ssh-skills` | Agent skills with frontmatter and safety prerequisites |
| `projects/open-ssh.ts/packages/open-ssh-win32-x64` | First native platform package |
| `wae.config.ts` | Native targets, platform packages, TS/UI/skills steps, staging and release set |

## First run

```sh
npm install --global @wae/wae
pnpm install
```

Commit `pnpm-lock.yaml` and `Cargo.lock` before enabling CI. `check-typescript.yml`
runs `pnpm install --frozen-lockfile`, so a missing lockfile fails the job by
design.

## Commands

```sh
pnpm run build         # wae build: native → TS → UI → skills → staging
pnpm run build:napi    # build one configured native target and stage it
pnpm run stage:napi    # restage an already built native artifact
pnpm run smoke:napi    # load the staged addon and verify capabilities
pnpm run check:rust    # fmt + clippy -D warnings + test
```

CLI surface:

```sh
open-ssh capabilities --json
open-ssh version
open-ssh session --transport ssh --json
open-ssh exec --transport rdp --json
open-ssh transfer --transport ssh --dry-run --json
open-ssh audit --kind agent --limit 20 --json
```

Exit codes: `0` success, `1` failure, `2` usage, `3` capability unavailable,
`4` canceled. `--json` emits `wae.cli-result/v0` envelopes.

## Audit

Every exported N-API capability is wrapped at the boundary through `wae::audit`
(`wae.audit/v0`). The domain supplies the capability id, the transport, the
target count, the redacted target summary, and a stable error code. Actor,
host, session, schema, timestamps, duration, and sanitisation stay in the
shared facility. Do not add a second audit schema.

## License

Apache-2.0. See the single repository-level `License.md`.
