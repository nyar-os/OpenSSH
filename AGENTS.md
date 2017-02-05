# AGENTS

This repository is public. Everything committed here — source, tests, fixtures,
docs, workflow YAML, commit messages, pull requests, issues, and CI logs — is
readable by anyone. Treat every artifact as publishable.

## De-sensitisation rules (mandatory)

Never commit data that identifies a real deployment, a real account, or real key
material. This includes:

- host names, IP addresses, and non-standard ports of any machine you tested
  against;
- user names, home directories, and file paths outside this repository;
- SSH host public keys, host key fingerprints, and `known_hosts` lines;
- private keys, passphrases, agent sockets, and copies of `authorized_keys`;
- captured handshakes: exchange hashes, shared secrets, server signatures, or
  version banners taken from a live target;
- audit records, debug dumps, packet captures, and trace output from a real
  session.

Rules that follow from this:

1. **Fixtures are synthetic.** Generate exchange material from constants or at
   test time. A vector copied from a live server is a leak, even when it only
   contains a public key.
2. **Debug hooks are opt-in and test-only.** Read targets from environment
   variables, keep the hook behind `#[cfg(test)]`, and never print `K`, `H`, or
   key material in release builds, normal logs, or audit records.
3. **Redact in diagnostics.** Errors and audit entries carry a truncated host
   hash and a user-supplied label, never a raw host, user, or key.
4. **Secrets stay outside the tree.** Credentials come from the environment or
   CI secrets. Never paste a token, password, or private key into the repository
   or a workflow file, and never echo one in a log.
5. **History counts.** If sensitive material lands in a commit, rewrite the
   affected history, force-push the branch, and rotate whatever was exposed
   (host key, authorized key, token). Removing it only from `HEAD` is not a fix.
6. **Report privately.** Security issues go to the maintainers directly, not
   into a public issue with a reproduction against a live host.

## Public-artifact rules

- No absolute paths, and no relative links that escape this repository.
- No references to internal planning or handoff documents, and no copies of
  them. Product semantics and conformance evidence live in this repository.
- Platform packages ship only the addon plus package metadata.

## Working in this repository

- one TypeScript package (`projects/open-ssh.ts/packages/open-ssh`) carries both
  the library (`new OpenSSH(options)`) and the `open-ssh` bin;
- every capability crosses the N-API boundary in
  `projects/open-ssh.rs/crates/napi`; TypeScript assembles commands with
  `@wae/commander` and owns no protocol logic;
- native addons are published per target: `win32-x64`, `darwin-arm64`,
  `darwin-x64`, `linux-x64`, `linux-arm64`.

## Checks before a commit

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm run build:ts
```

`cargo check` alone is not evidence. Protocol changes need a real handshake or
an interop run; see the interop test for the environment-driven entry point.

## Commit messages

Follow the workspace convention: start with one gitmoji, wrap identifiers in
backticks, do not use `;`, and do not put versions in the message.
