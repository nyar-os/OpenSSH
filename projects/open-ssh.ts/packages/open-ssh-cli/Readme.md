# @wae/open-ssh-cli

`open-ssh` command line entry.

- Non-interactive. Decisions are made by exit code, not by prose.
- `--json` emits `wae.cli-result/v0` envelopes on stdout.
- Capability ids are transport-neutral. `--transport` selects `ssh` or `rdp`.
- Mutating commands accept `--dry-run`.

Exit codes: `0` success, `1` failure, `2` usage, `3` capability unavailable, `4` canceled.

In this skeleton round every domain capability refuses with `not_implemented`. `exec` over `rdp` is refused because RDP has no command channel.
