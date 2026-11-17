// Nifty project configuration.
// See @doki-land/nifty for defineConfig, format presets, authorMap path, and lint rules.
export default {
    // The workspace keeps its packages under `projects/<product>.ts/packages`,
    // which is outside Nifty's default discovery roots, so the publish set is
    // declared explicitly.
    publish: {
        packages: [
            '@wae/open-ssh-win32-x64',
            '@wae/open-ssh-darwin-arm64',
            '@wae/open-ssh-darwin-x64',
            '@wae/open-ssh-linux-x64',
            '@wae/open-ssh-linux-arm64',
            '@wae/open-ssh',
        ],
    },
    // `nifty trust` configures npm Trusted Publisher from this block, and the
    // release workflow must match these three values exactly.
    trust: {
        npm: {
            repo: 'nyar-os/OpenSSH',
            file: 'publish-npm.yml',
            environment: 'NPM_PUBLISH',
        },
    },
};
