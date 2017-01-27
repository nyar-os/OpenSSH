# `@wae/open-ssh`

Library and `open-ssh` command for the OpenSSH application.

- one author surface: `new OpenSSH(options)` with per-call overrides
- loads the platform native addon lazily and fails with `unsupported_platform`
  when no addon exists for the current target
- owns the structured `AppError` used by every consumer
- ships the `open-ssh` bin (built with `@wae/commander`) and the `en-US` /
  `zh-CN` locale catalogs
- published native addons: `win32-x64`, `darwin-arm64`, `darwin-x64`,
  `linux-x64`, `linux-arm64`

```js
import { OpenSSH } from '@wae/open-ssh';

const ssh = new OpenSSH({
    host: '10.0.0.5',
    user: 'deploy',
    identityPath: '/home/me/.ssh/id_ed25519',
    hostKeySha256: 'SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
});

const session = ssh.connect();
console.log(session.serverVersion, session.hostKeySha256);

const result = ssh.exec('uname -a');
console.log(result.exitCode, result.stdout);

const uploaded = ssh.transfer({
    direction: 'upload',
    localPath: './build/app.tar',
    remotePath: '/srv/app.tar',
    resume: true,
});
console.log(uploaded.bytes, uploaded.resumedFrom);

// Every other domain capability still refuses with `not_implemented`.
ssh.invoke('host-inventory');
```

The same package installs the command:

```sh
open-ssh connect --transport ssh --host 10.0.0.5 --user deploy \
  --identity ~/.ssh/id_ed25519 --host-key-sha256 SHA256:xxxx --json
```

See the repository `Readme.md` for build and test commands.
