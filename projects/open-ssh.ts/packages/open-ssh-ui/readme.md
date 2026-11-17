# Open Ssh UI

VMZ application shell for the Open Ssh native host.

```bash
pnpm run build
```

`vmz build . --profile static` writes to `dist/static`. The root `wae build`
staging step copies it to `packages/open-ssh/dist/gui`, which is the directory
the N-API host loads by default, so this package never copies files itself.

The page talks to the host through the WebView bridge:

- send `{ "type": "capabilities" }`, `{ "type": "inspect", "root": "..." }`,
  `{ "type": "installPlan", "noShortcut": true }`, or `{ "type": "close" }`
- receive `{ "ok": true, "data": ... }` or
  `{ "ok": false, "error": { "code", "capability", "platform", "message" } }`

Keep domain logic in `crates/core`. The page renders results, it does not
re-implement scanning or install planning.
