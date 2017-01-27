/**
 * Typed library and command surface over the N-API boundary.
 *
 * One class owns every capability. `new OpenSSH(options)` supplies the target
 * defaults and each method accepts overrides, so callers never rebuild an
 * options object per call. The `open-ssh` `bin` in `cli.ts` is a thin
 * `@wae/commander` assembly over this class, and it owns no protocol logic.
 */
import { AppError, fromNativeError } from './errors.js';
import { loadNative, supportedPlatforms } from './native.js';

export type { PlatformArch } from './native.js';

/** Capability availability states. `null` means available. */
export type CapabilityState = 'unsupported_platform' | 'not_implemented' | 'dependency_blocked';

/** Transport adapters known to the product. */
export type Transport = 'ssh' | 'rdp';

/** How one transport adapter relates to a capability. */
export interface TransportRow {
    transport: Transport;
    state: CapabilityState | null;
    code: string | null;
    reason: string;
}

/** One capability row. */
export interface CapabilityItem {
    id: string;
    state: CapabilityState | null;
    code: string | null;
    reason: string;
    detail: string;
    transports: TransportRow[];
}

/** Capability report, including the `gui` row added by the native boundary. */
export interface CapabilitiesReport {
    app: string;
    platform: string;
    arch: string;
    version: string;
    transports: Transport[];
    items: CapabilityItem[];
    notes: string[];
}

/** GUI open options. */
export interface GuiOptions {
    contentDir?: string;
    title?: string;
}

/** Caller identity used by the shared audit facility. */
export interface AuditActor {
    actorKind?: 'user' | 'agent';
    actorId?: string;
    actorSource?: string;
    session?: string;
    host?: string;
}

/** Audit query filter. */
export interface AuditQuery {
    kind?: 'user' | 'agent';
    id?: string;
    fromMs?: number;
    toMs?: number;
    capability?: string;
    limit?: number;
}

/** One audit record as stored by the shared facility. */
export type AuditRecord = Record<string, unknown>;

/** Success payload shared by the meta capabilities. */
export interface OkResult {
    ok: true;
}

/** Authentication method used by one call. */
export type ExecAuthMethod = 'password' | 'publickey';

/**
 * Target defaults shared by every capability call.
 *
 * The constructor takes the same shape, and each method accepts a partial
 * override. Authentication is either `password` or `identityPath`, never both.
 */
export interface EndpointOptions {
    transport?: Transport;
    host?: string;
    port?: number;
    user?: string;
    /** Remote password. Mutually exclusive with `identityPath`. */
    password?: string;
    /** Path to an unencrypted `ssh-ed25519` private key. */
    identityPath?: string;
    /** Required `SHA256:` host key fingerprint. */
    hostKeySha256?: string;
    timeoutMs?: number;
}

/** Constructor options, identical to the per-call overrides. */
export type OpenSSHOptions = EndpointOptions;

/** Result of one successful `connect` call. */
export interface ConnectResult {
    transport: 'ssh';
    hostHash: string;
    port: number;
    user: string;
    authMethod: ExecAuthMethod;
    /** Server identification string without the trailing CRLF. */
    serverVersion: string;
    /** Verified `SHA256:` host key fingerprint. */
    hostKeySha256: string;
    kexAlgorithm: string;
    hostKeyAlgorithm: string;
    cipher: string;
    mac: string;
    durationMs: number;
}

/** What a preview `connect` resolves without connecting. */
export interface ConnectPreview {
    transport: 'ssh';
    hostHash: string;
    port: number;
    user: string;
    authMethod: ExecAuthMethod;
    hostKeySha256: string;
    timeoutMs: number;
}

/** Result of one successful `exec` call. */
export interface ExecResult {
    transport: 'ssh';
    hostHash: string;
    port: number;
    user: string;
    authMethod: ExecAuthMethod;
    /** Remote exit status, or `null` when the server reported none. */
    exitCode: number | null;
    stdout: string;
    stderr: string;
    stdoutBytes: number;
    stderrBytes: number;
    durationMs: number;
}

/** What a preview `exec` resolves without connecting. */
export interface ExecPreview {
    transport: 'ssh';
    hostHash: string;
    port: number;
    user: string;
    authMethod: ExecAuthMethod;
    commandBytes: number;
    hostKeySha256: string;
    timeoutMs: number;
}

/** Which way bytes move in one `transfer` call. */
export type TransferDirection = 'upload' | 'download' | 'list';

/** One entry returned by a directory listing. */
export interface TransferEntry {
    name: string;
    size: number;
    isDir: boolean;
}

/** Options for one `transfer` call. */
export interface TransferOptions extends EndpointOptions {
    direction: TransferDirection;
    /** Remote file or directory. Escapes and empty values are refused. */
    remotePath: string;
    /** Local file for upload and download. Ignored for listings. */
    localPath?: string;
    /** Continue from the bytes already present on the other side. */
    resume?: boolean;
    /** Write human-readable progress to stderr while bytes move. */
    progress?: boolean;
}

/** Result of one successful `transfer` call. */
export interface TransferResult {
    transport: 'ssh';
    hostHash: string;
    port: number;
    user: string;
    authMethod: ExecAuthMethod;
    direction: TransferDirection;
    remotePath: string;
    localPath: string | null;
    /** Bytes moved by this call, excluding any resumed prefix. */
    bytes: number;
    /** Offset this call resumed from. */
    resumedFrom: number;
    /** Directory entries, empty for uploads and downloads. */
    entries: TransferEntry[];
    durationMs: number;
}

/** What a preview `transfer` resolves without connecting. */
export interface TransferPreview {
    transport: 'ssh';
    hostHash: string;
    port: number;
    user: string;
    authMethod: ExecAuthMethod;
    direction: TransferDirection;
    remotePath: string;
    localPath: string | null;
    resume: boolean;
    /** Local file size for uploads, `null` when only the server knows. */
    plannedBytes: number | null;
    hostKeySha256: string;
    timeoutMs: number;
}

/** Normalized endpoint fields, with the constructor defaults applied. */
interface ResolvedEndpoint {
    transport: Transport;
    host: string;
    port: number;
    user: string;
    password?: string;
    identityPath?: string;
    hostKeySha256: string;
    timeoutMs?: number;
}

/**
 * A client for one set of target defaults.
 *
 * ```ts
 * const ssh = new OpenSSH({
 *     host: 'example.internal',
 *     user: 'deploy',
 *     identityPath: '/home/me/.ssh/id_ed25519',
 *     hostKeySha256: 'SHA256:...',
 * });
 * const run = ssh.exec('uname -a');
 * ```
 */
export class OpenSSH {
    readonly #defaults: EndpointOptions;

    constructor(options: OpenSSHOptions = {}) {
        this.#defaults = { ...options };
    }

    /** Supported `platform-arch` keys of the published native packages. */
    static supportedPlatforms(): string[] {
        return [...supportedPlatforms()];
    }

    /** Native addon version. */
    version(): string {
        return this.#invoke(() => loadNative().version());
    }

    /** Capability report, including rows owned by the upstream facade. */
    capabilities(): CapabilitiesReport {
        return this.#invoke(() => loadNative().capabilities() as CapabilitiesReport);
    }

    /**
     * Resolve one domain capability by its stable id.
     *
     * `transport` is a separate dimension and never part of the id. Available
     * capabilities have dedicated methods, so this raises their refusal instead
     * of silently doing nothing.
     */
    invoke<T = unknown>(capability: string, transport?: Transport): T {
        return this.#invoke(() => loadNative().invoke(capability, transport) as T);
    }

    /** Configure the shared audit facility for this process. */
    configureAudit(actor: AuditActor): OkResult {
        return this.#invoke(() => loadNative().configureAudit({ ...actor }) as OkResult);
    }

    /** Read audit entries for the current actor as structured records. */
    auditQuery(filter: AuditQuery = {}): AuditRecord[] {
        const json = this.#invoke(() => loadNative().auditQuery({ ...filter }));
        return this.#invoke(() => JSON.parse(json) as AuditRecord[]);
    }

    /**
     * Connect, verify the pinned host key, authenticate, and disconnect.
     *
     * The call proves the target and the credentials and reports the negotiated
     * session without running a command.
     */
    connect(options: EndpointOptions = {}): ConnectResult {
        const endpoint = this.#endpoint(options);
        return this.#invoke(() => loadNative().connect({ ...endpoint }) as ConnectResult);
    }

    /** Resolve a `connect` request without opening a connection. */
    previewConnect(options: EndpointOptions = {}): ConnectPreview {
        const endpoint = this.#endpoint(options);
        return this.#invoke(() => loadNative().connect({ ...endpoint, dryRun: true }) as ConnectPreview);
    }

    /** Run one command over `ssh` and return its captured output. */
    exec(command: string, options: EndpointOptions = {}): ExecResult {
        const endpoint = this.#endpoint(options);
        if (!command.trim()) {
            throw new AppError({ code: 'invalid_argument', message: '`command` must not be empty' });
        }
        return this.#invoke(() => loadNative().exec({ ...endpoint, command }) as ExecResult);
    }

    /** Resolve an `exec` request without opening a connection. */
    previewExec(command: string, options: EndpointOptions = {}): ExecPreview {
        const endpoint = this.#endpoint(options);
        if (!command.trim()) {
            throw new AppError({ code: 'invalid_argument', message: '`command` must not be empty' });
        }
        return this.#invoke(() => loadNative().exec({ ...endpoint, command, dryRun: true }) as ExecPreview);
    }

    /** Upload, download, or list files over `ssh`. */
    transfer(options: TransferOptions): TransferResult {
        const { direction, remotePath, localPath, resume, progress, ...endpointOptions } = options;
        const endpoint = this.#endpoint(endpointOptions);
        return this.#invoke(
            () =>
                loadNative().transfer({
                    ...endpoint,
                    direction,
                    remotePath,
                    ...(localPath === undefined ? {} : { localPath }),
                    ...(resume === undefined ? {} : { resume }),
                    ...(progress === undefined ? {} : { progress }),
                }) as TransferResult,
        );
    }

    /** Resolve a `transfer` request without opening a connection. */
    previewTransfer(options: TransferOptions): TransferPreview {
        const { direction, remotePath, localPath, resume, progress, ...endpointOptions } = options;
        const endpoint = this.#endpoint(endpointOptions);
        return this.#invoke(
            () =>
                loadNative().transfer({
                    ...endpoint,
                    direction,
                    remotePath,
                    ...(localPath === undefined ? {} : { localPath }),
                    ...(resume === undefined ? {} : { resume }),
                    ...(progress === undefined ? {} : { progress }),
                    dryRun: true,
                }) as TransferPreview,
        );
    }

    /** Open the GUI window. */
    openGui(options: GuiOptions = {}): { backend: string } {
        return this.#invoke(() => loadNative().openGui({ ...options }) as { backend: string });
    }

    /** Pump one GUI event batch. */
    pumpEvents(): boolean {
        return this.#invoke(() => loadNative().pumpEvents());
    }

    /** Request GUI close. */
    closeGui(): boolean {
        return this.#invoke(() => loadNative().closeGui());
    }

    /** Whether the GUI window is still open. */
    isGuiOpen(): boolean {
        return this.#invoke(() => loadNative().isGuiOpen());
    }

    /**
     * Open the GUI and pump until the window closes.
     *
     * The host owns the event loop, so the process stays alive without spawning
     * a second runtime.
     */
    async runGui(options: GuiOptions = {}): Promise<string> {
        const opened = this.openGui(options);
        while (this.pumpEvents()) {
            await new Promise((resolve) => setTimeout(resolve, 16));
        }
        this.closeGui();
        return opened.backend;
    }

    /** Merge the constructor defaults with one call's overrides. */
    #endpoint(options: EndpointOptions): ResolvedEndpoint {
        const merged: EndpointOptions = { ...this.#defaults, ...options };
        const host = merged.host?.trim();
        if (!host) {
            throw new AppError({ code: 'invalid_argument', message: '`host` is required' });
        }
        const user = merged.user?.trim();
        if (!user) {
            throw new AppError({ code: 'invalid_argument', message: '`user` is required' });
        }
        const hostKeySha256 = merged.hostKeySha256?.trim();
        if (!hostKeySha256) {
            throw new AppError({
                code: 'host_key_unverified',
                message: 'a pinned `hostKeySha256` fingerprint is required, and this client never trusts an unknown key',
            });
        }
        if ((merged.password === undefined) === (merged.identityPath === undefined)) {
            throw new AppError({ code: 'invalid_argument', message: 'pass exactly one of `password` or `identityPath`' });
        }
        return {
            transport: merged.transport ?? 'ssh',
            host,
            port: merged.port ?? 22,
            user,
            ...(merged.password === undefined ? {} : { password: merged.password }),
            ...(merged.identityPath === undefined ? {} : { identityPath: merged.identityPath }),
            hostKeySha256,
            ...(merged.timeoutMs === undefined ? {} : { timeoutMs: merged.timeoutMs }),
        };
    }

    /** Convert native boundary failures into `AppError`. */
    #invoke<T>(run: () => T): T {
        try {
            return run();
        }
        catch (error) {
            throw fromNativeError(error);
        }
    }
}

export { AppError, fromNativeError } from './errors.js';
