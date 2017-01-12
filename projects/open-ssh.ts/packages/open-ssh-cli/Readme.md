# @wae/open-ssh-cli

`open-ssh` command line entry.

- Non-interactive. Decisions are made by exit code, not by prose.
- `--json` emits `wae.cli-result/v0` envelopes on stdout.
- Capability ids are transport-neutral. `--transport` selects `ssh` or `rdp`.
- Mutating commands accept `--dry-run`.

Exit codes: `0` success, `1` failure, `2` usage, `3` capability unavailable, `4` canceled.

`exec` and `transfer` are the available domain capabilities.

`exec` runs one command over `ssh`, writes the captured stdout and stderr
unchanged, and prints a summary on stderr. The remote exit status is reported as
`exitCode` in the payload, and the process exits `0` only when that status is
`0`. A missing remote status counts as a failure. `exec` over `rdp` is refused
because RDP has no command channel.

`transfer` uploads, downloads, or lists one SFTP path over `ssh`. `--direction`
selects the operation, `--local` and `--remote` name the paths, `--resume`
continues from the bytes already present on the other side, and `--progress`
writes human-readable progress to stderr. The payload always reports the exact
`bytes` moved by this call, the `resumedFrom` offset, and the `durationMs`.
Listings return sorted `entries`. Failures stay distinct: `remote_not_found`,
`permission_denied`, `disk_full`, `connection_lost`, `transfer_failed`, and
`path_rejected` for escapes or empty paths. Every other capability still refuses
with `not_implemented`.

```sh
OPEN_SSH_PASSWORD=... open-ssh exec --transport ssh --host 10.0.0.5 --user deploy \
  --command "uname -a" --password-env OPEN_SSH_PASSWORD \
  --host-key-sha256 SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

open-ssh exec --transport ssh --host 10.0.0.5 --user deploy \
  --command "uname -a" --identity ~/.ssh/id_ed25519 \
  --host-key-sha256 SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --json

open-ssh transfer --host 10.0.0.5 --user deploy --direction upload \
  --local ./build/app.tar --remote /srv/app.tar --resume --progress \
  --identity ~/.ssh/id_ed25519 \
  --host-key-sha256 SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

open-ssh transfer --host 10.0.0.5 --user deploy --direction list --remote /srv \
  --identity ~/.ssh/id_ed25519 \
  --host-key-sha256 SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --json
```

A host key pin is mandatory. An unknown or mismatched key fails instead of being
trusted. `--dry-run` resolves the target without opening a connection and prints
the transport, user, port, auth method, pin, command size, and deadline.
