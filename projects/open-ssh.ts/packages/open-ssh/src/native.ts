/**
 * Lazy loader for the platform-native addon.
 *
 * The addon is an optional dependency. It is loaded only when a native
 * capability is called, so `--help`, `version`, and locale resolution work on
 * machines without the binary.
 */
import { createRequire } from 'node:module';
import { AppError } from './errors.js';

const require = createRequire(import.meta.url);
const PLATFORM_PACKAGE = '@wae/open-ssh-win32-x64';

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
    exec(options: NativeExecOptions): unknown;
    transfer(options: NativeTransferOptions): unknown;
    invoke(capability: string, transport?: string): unknown;
    cliContract(): unknown;
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

/** Load the native addon once. */
export function loadNative(): NativeBindings {
    if (cached) return cached;
    try {
        cached = require(PLATFORM_PACKAGE) as NativeBindings;
        return cached;
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new AppError({
            code: 'native_unavailable',
            platform: `${process.platform}-${process.arch}`,
            message:
                `cannot load ${PLATFORM_PACKAGE}: ${message}\n` +
                'Run `pnpm run build:napi` from the repository root, ' +
                'or install the matching platform package.',
        });
    }
}
