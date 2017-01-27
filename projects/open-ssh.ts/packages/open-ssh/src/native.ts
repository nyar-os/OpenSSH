/**
 * Lazy loader for the platform-native addon.
 *
 * Every supported platform ships its own optional dependency, and the addon is
 * resolved from the matching package only. A missing platform or a missing
 * artifact raises a structured error instead of falling back to a pure
 * JavaScript implementation, because the protocol lives only in the addon.
 */
import { createRequire } from 'node:module';

import { AppError } from './errors.js';

const require = createRequire(import.meta.url);

/** One published native target. */
export type PlatformArch = 'win32-x64' | 'darwin-x64' | 'darwin-arm64' | 'linux-x64' | 'linux-arm64';

/** Platform packages published next to this one. */
const PLATFORM_PACKAGES: Record<PlatformArch, string> = {
    'win32-x64': '@wae/open-ssh-win32-x64',
    'darwin-x64': '@wae/open-ssh-darwin-x64',
    'darwin-arm64': '@wae/open-ssh-darwin-arm64',
    'linux-x64': '@wae/open-ssh-linux-x64',
    'linux-arm64': '@wae/open-ssh-linux-arm64',
};

/** Every `platform-arch` key that has a published addon. */
export function supportedPlatforms(): PlatformArch[] {
    return Object.keys(PLATFORM_PACKAGES) as PlatformArch[];
}

/** The current host target, or `null` when no addon is published for it. */
function currentPlatformArch(): PlatformArch | null {
    const key = `${process.platform}-${process.arch}`;
    return Object.hasOwn(PLATFORM_PACKAGES, key) ? (key as PlatformArch) : null;
}

/** Options accepted by the native `connect` export. */
export interface NativeConnectOptions {
    transport?: string;
    host: string;
    port?: number;
    user: string;
    password?: string;
    identityPath?: string;
    hostKeySha256?: string;
    timeoutMs?: number;
    dryRun?: boolean;
}

/** Options accepted by the native `exec` export. */
export interface NativeExecOptions {
    transport?: string;
    host: string;
    port?: number;
    user: string;
    command: string;
    password?: string;
    identityPath?: string;
    hostKeySha256?: string;
    timeoutMs?: number;
    dryRun?: boolean;
}

/** Options accepted by the native `transfer` export. */
export interface NativeTransferOptions {
    transport?: string;
    host: string;
    port?: number;
    user: string;
    direction: 'upload' | 'download' | 'list';
    remotePath: string;
    localPath?: string;
    password?: string;
    identityPath?: string;
    hostKeySha256?: string;
    timeoutMs?: number;
    resume?: boolean;
    progress?: boolean;
    dryRun?: boolean;
}

/** Raw surface exported by the Rust `napi` crate. */
export interface NativeBindings {
    version(): string;
    capabilities(): unknown;
    connect(options: NativeConnectOptions): unknown;
    exec(options: NativeExecOptions): unknown;
    transfer(options: NativeTransferOptions): unknown;
    invoke(capability: string, transport?: string): unknown;
    openGui(options?: { contentDir?: string; title?: string }): unknown;
    pumpEvents(): boolean;
    closeGui(): boolean;
    isGuiOpen(): boolean;
    configureAudit(options: {
        actorKind?: string;
        actorId?: string;
        actorSource?: string;
        session?: string;
        host?: string;
    }): unknown;
    auditQuery(filter?: {
        kind?: string;
        id?: string;
        fromMs?: number;
        toMs?: number;
        capability?: string;
        limit?: number;
    }): string;
}

let cached: NativeBindings | null = null;

/** Load the addon for the current target, or raise a structured error. */
export function loadNative(): NativeBindings {
    if (cached) return cached;
    const platform = `${process.platform}-${process.arch}`;
    const target = currentPlatformArch();
    if (target === null) {
        throw new AppError({
            code: 'unsupported_platform',
            platform,
            attempts: [],
            message:
                `no native addon is published for \`${platform}\`. ` +
                `Supported targets: ${supportedPlatforms().join(', ')}.`,
        });
    }
    const packageName = PLATFORM_PACKAGES[target];
    try {
        cached = require(packageName) as NativeBindings;
        return cached;
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new AppError({
            code: 'native_unavailable',
            platform,
            attempts: [packageName],
            message:
                `cannot load \`${packageName}\`: ${message}\n` +
                'Run `pnpm run build:napi` from the repository root, or install the matching platform package.',
        });
    }
}
