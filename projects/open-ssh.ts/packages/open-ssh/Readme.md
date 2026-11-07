# `@wae/open-ssh`

Facade for the OpenSSH application.

- loads the platform native addon lazily
- exposes the typed capability, audit, CLI-contract, and GUI surface
- owns the structured `AppError` used by every consumer
- ships the `en-US` and `zh-CN` locale catalogs

The product `bin` lives in [`@wae/open-ssh-cli`](../open-ssh-cli). This package
must never expose a `bin` of its own.

```js
import { capabilities, invokeCapability } from '@wae/open-ssh';

const report = capabilities();
console.log(report.items.map((item) => [item.id, item.state]));

// Skeleton round: every domain capability refuses with `not_implemented`.
invokeCapability('host-inventory');
```

See the repository `Readme.md` for build and test commands.
