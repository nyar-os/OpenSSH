---
name: workflow
description: Drive the transport-neutral OpenSSH CLI to read the capability matrix, run one command over SSH, and preview file transfer without touching host state.
---

# OpenSSH agent workflow

This skill drives the `open-ssh` CLI. The CLI is non-interactive and every
command returns a stable exit code:

- `0` success
- `1` runtime failure
- `2` usage or validation failure
- `3` structured capability failure (`unsupported_platform`, `not_implemented`,
  `dependency_blocked`)
- `4` canceled

Prefer `--json`. Every result is a `wae.cli-result/v0` envelope:
`{ "schema", "ok": true, "data": ... }` or
`{ "schema", "ok": false, "error": { "code", "capability", "platform", "message" } }`.
Do not parse human prose.

## Capability ids are goals, not protocols

`connect`, `exec`, `transfer`, and `session` are transport-neutral. The adapter
is a separate dimension selected with `--transport ssh|rdp`. Never infer support
from a capability id. Read the per-transport rows in the report.

## Read-only discovery

1. Read the matrix. Each row lists `transports[]` with `transport`, `state`,
   `code`, and `reason`. `state: null` means the transport supports the
   capability. A non-null `state` is a refusal that must not be attempted.

   `open-ssh capabilities --json`

2. RDP has no command channel. `exec --transport rdp` is refused and stays
   refused. Report the refusal instead of retrying over another protocol.

   `open-ssh exec --transport=rdp --json`

3. Enumerate sessions and their state.

   `open-ssh session --transport=<ssh|rdp> --json`

## Command execution over SSH

`exec` is the only available domain capability. It needs an explicit host key
pin; the product never trusts an unknown key and never offers TOFU.

6. Preview first. The preview resolves the target and the pin without opening a
   connection.

   `open-ssh exec --transport=ssh --host=<host> --user=<user> --command="<cmd>" --identity=<path> --host-key-sha256=<SHA256:...> --dry-run --json`

7. Run the command. Pass the password through `--password-env` so it never
   appears in the process command line or in audit records. Do not put a
   password in `--command` or in any other flag.

   `open-ssh exec --transport=ssh --host=<host> --user=<user> --command="<cmd>" --password-env=<VAR> --host-key-sha256=<SHA256:...> --json`

8. Read `data.exitCode`, `data.stdout`, `data.stderr`, `data.stdoutBytes`, and
   `data.stderrBytes`. The process exits `0` only when `exitCode` is `0`. A
   non-zero remote status keeps its exact value in `exitCode` and exits `1`.

   Error codes are distinct: `connect_failed`, `connect_timeout`,
   `negotiation_failed`, `host_key_unverified`, `host_key_mismatch`,
   `auth_failed`, `identity_rejected`, `protocol_error`, `exec_failed`. Do not
   collapse them into one retry rule. `host_key_mismatch` must be reported, not
   bypassed.

## File transfer

Transfer stays `not_implemented` in this round. Preview the plan first and show
it to the user. RDP transfer uses drive redirection and SSH transfer uses SFTP.
The channel is selected by `--transport`, never by a capability id.

4. Preview. `--dry-run` must come before any apply form.

   `open-ssh transfer --transport=<ssh|rdp> --dry-run --json`

5. Apply only after explicit confirmation. Overwrites and deletions are
   confirmed individually. Deleting a file the tool just uploaded is an
   explicit action and is never automatic.

## Audit

Every domain call is recorded by the shared audit facility with the capability
id and the transport as separate fields. Use `--actor-kind agent` and a stable
`--actor` id so the records are attributable.

   `open-ssh audit --kind <user|agent> --capability <id> --limit <n> --json`

## Safety

- `exec` is available over `ssh` only. Every other domain capability refuses
  with `not_implemented`. A refusal is not a success. Do not fall back to an
  external `ssh`, `sftp`, `scp`, `mstsc`, or `winrs` process.
- Do not execute a mutating command without explicit confirmation（确认）from the
  user after the dry-run preview.
- Do not retry a structured capability failure with elevated privileges. Report
  the `code`, `capability`, and `platform` fields instead.
- Treat `--json` output as the contract. Exit code `3` means the capability is
  unavailable on this platform, is not implemented, or is not carried by the
  selected transport.
