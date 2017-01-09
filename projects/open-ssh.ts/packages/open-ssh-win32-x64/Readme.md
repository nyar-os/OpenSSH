# open-ssh-win32-x64

Platform package for the `open-ssh` native addon on Windows x64.

The `*.node` binary is produced by `wae native build` from the target declared in
`wae.config.ts` and copied into this directory. It is not committed. Build
before publishing:

```bash
pnpm run build:napi
```

The app package lists this package under `optionalDependencies`, so npm and
pnpm install it only on matching `os` / `cpu` targets.
