# `@wae/open-ssh`

Facade for the OpenSSH application.

- loads the platform native addon lazily
- exposes the typed capability, audit, CLI-contract, and GUI surface
- owns the structured `AppError` used by every consumer
- ships the `en-US` and `zh-CN` locale catalogs

The product `bin` lives in [`@wae/open-ssh-cli`](../open-ssh-cli). This package
must never expose a `bin` of its own.

```js
import { exec, capabilities, invokeCapability } from '@wae/open-ssh';

const report = capabilities();
console.log(report.items.map((item) => [item.id, item.state]));

// `exec` is the only available domain capability.
const result = exec({
    transport: 'ssh',
    host: '10.0.0.5',
    user: 'deploy',
    command: 'uname -a',
    identityPath: '/home/me/.ssh/id_ed25519',
    hostKeySha256: 'SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
});
console.log(result.exitCode, result.stdout);

// Every other domain capability still refuses with `not_implemented`.
invokeCapability('host-inventory');
```

See the repository `Readme.md` for build and test commands.
