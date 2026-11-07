/**
 * OpenSSH build configuration.
 *
 * Plain literal data: `wae` parses this file without executing it, so a config
 * cannot run commands, spawn processes, or branch on `process.env`. Every
 * relative path resolves against this directory.
 *
 * `wae build` runs `native → ts → ui → skills → staging` in that order and
 * fails with a stable `build_*` code instead of skipping a missing artifact.
 */
import { defineConfig } from '@wae/wae';

export default defineConfig({
    native: {
        crate: 'open-ssh-napi',
        cdylib: 'open_ssh_napi',
        profile: 'release',
        targets: [
            {
                platform: 'win32',
                arch: 'x64',
                triple: 'x86_64-pc-windows-msvc',
                package: '@wae/open-ssh-win32-x64',
                nodeFile: 'open-ssh.win32-x64.node',
                dir: 'projects/open-ssh.ts/packages/open-ssh-win32-x64',
            },
        ],
    },
    packages: [
        {
            name: '@wae/open-ssh-win32-x64',
            dir: 'projects/open-ssh.ts/packages/open-ssh-win32-x64',
            os: ['win32'],
            cpu: ['x64'],
            main: 'open-ssh.win32-x64.node',
        },
    ],
    build: {
        ts: { packages: ['@wae/open-ssh', '@wae/open-ssh-cli'] },
        ui: { package: '@wae/open-ssh-ui' },
        stage: [
            {
                from: 'projects/open-ssh.ts/packages/open-ssh-ui/dist/static',
                to: 'projects/open-ssh.ts/packages/open-ssh-cli/dist/gui',
                clean: true,
            },
        ],
        outputs: ['projects/open-ssh.ts/packages/open-ssh-cli/dist/gui/index.html'],
    },
    skills: {
        packages: [
            {
                dir: 'projects/open-ssh.ts/packages/open-ssh-skills/skills',
                packageJson: 'projects/open-ssh.ts/packages/open-ssh-skills/package.json',
                appPackageJson: 'projects/open-ssh.ts/packages/open-ssh/package.json',
                cliEntry: 'projects/open-ssh.ts/packages/open-ssh-cli/dist/cli.js',
                commandName: 'open-ssh',
            },
        ],
    },
    // The publishable set is the non-private platform package, the TypeScript
    // packages under `build.ts`, and any non-private UI package. Skills is
    // `private` in this round, so it is not part of the release set.
    release: {
        registry: 'https://registry.npmjs.org',
        tagPattern: '^v(\\d+\\.\\d+\\.\\d+)$',
        packages: [
            { dir: 'projects/open-ssh.ts/packages/open-ssh-win32-x64' },
            { dir: 'projects/open-ssh.ts/packages/open-ssh' },
            { dir: 'projects/open-ssh.ts/packages/open-ssh-cli' },
        ],
    },
    // `wae build` validates this CI contract: the declared workflow files must
    // exist, `requiredJobs` must be real job ids, and `repo` must match
    // `Cargo.toml#repository`. Claim `shaBinding` only when a workflow actually
    // binds `GITHUB_SHA` to the release tag.
    ci: {
        repo: 'nyar-os/OpenSSH',
        workflows: ['check-rust.yml', 'check-typescript.yml'],
        shaBinding: false,
    },
    // `wae build` writes these into the app CLI as `dist/wae-runtime.json`.
    // `shortcutDefault` is the install command's default (a desktop shortcut is
    // created unless `--no-shortcut` is passed), and every capability call
    // resolves the audit actor from the channels declared here.
    install: { shortcutDefault: true },
    audit: { actor: { kind: 'flag', id: 'flag', source: 'env' } },
});
