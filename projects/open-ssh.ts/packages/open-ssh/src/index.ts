/**
 * Typed library surface over the N-API boundary.
 *
 * Every function forwards to the native addon and converts structured native
 * errors into `AppError`. The CLI, skills, and GUI consume this module so they
 * share one error contract. This package owns no `bin`.
 */
import { AppError, fromNativeError } from './errors.js';
import { loadNative } from './native.js';

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

/** One command row of the CLI contract. */
export interface CliCommandRow {
    id: string;
    capability: string;
    kind: 'meta' | 'domain';
    state: CapabilityState | null;
    code: string | null;
}

/** One exit code row of the CLI contract. */
export interface CliExitCodeRow {
    name: 'success' | 'failure' | 'usage' | 'capability' | 'canceled';
    code: number;
}

/** Stable CLI contract mirrored by the Rust `open-ssh-cli` crate. */
export interface CliContract {
    schema: string;
    app: string;
    envelope: string;
    exitCodes: CliExitCodeRow[];
    commands: CliCommandRow[];
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

/** Success payload shared by the meta capabilities. */
export interface OkResult {
    ok: true;
}

function invoke<T>(run: () => T): T {
    try {
        return run();
    }
    catch (error) {
        throw fromNativeError(error);
    }
}

/** Native addon version. */
export function version(): string {
    return invoke(() => loadNative().version());
}

/** Capability report, including rows owned by the upstream facade. */
export function capabilities(): CapabilitiesReport {
    return invoke(() => loadNative().capabilities() as CapabilitiesReport);
}

/**
 * Resolve one domain capability by its stable id.
 *
 * `transport` is a separate dimension and never part of the id. Passing one
 * selects a more precise refusal, for example `exec` over `rdp` reports that RDP
 * has no command channel.
 *
 * In the skeleton round every registered domain capability refuses with its
 * `not_implemented` code. Callers must not treat an exception here as a
 * successful result.
 */
export function invokeCapability<T = unknown>(capability: string, transport?: Transport): T {
    return invoke(() => loadNative().invoke(capability, transport) as T);
}

/** Stable CLI contract shared with `@wae/open-ssh-cli`. */
export function cliContract(): CliContract {
    return invoke(() => loadNative().cliContract() as CliContract);
}

/** Configure the shared audit facility for this process. */
export function configureAudit(actor: AuditActor): OkResult {
    return invoke(() => loadNative().configureAudit(actor) as OkResult);
}

/** Read audit entries for the current actor as structured records. */
export function auditQuery(filter: AuditQuery = {}): Record<string, unknown>[] {
    const json = invoke(() => loadNative().auditQuery(filter));
    return invoke(() => JSON.parse(json) as Record<string, unknown>[]);
}

/** Open the GUI window. */
export function openGui(options: GuiOptions = {}): { backend: string } {
    return invoke(() => loadNative().openGui(options) as { backend: string });
}

/** Pump one GUI event batch. */
export function pumpEvents(): boolean {
    return invoke(() => loadNative().pumpEvents());
}

/** Request GUI close. */
export function closeGui(): boolean {
    return invoke(() => loadNative().closeGui());
}

/** Whether the GUI window is still open. */
export function isGuiOpen(): boolean {
    return invoke(() => loadNative().isGuiOpen());
}

/**
 * Open the GUI and pump until the window closes.
 *
 * The host owns the event loop, so the process stays alive without spawning a
 * second runtime. Implemented here once so the CLI and plugins share it.
 */
export async function runGui(options: GuiOptions = {}): Promise<string> {
    const opened = openGui(options);
    while (pumpEvents()) {
        await new Promise((resolve) => setTimeout(resolve, 16));
    }
    closeGui();
    return opened.backend;
}

export { AppError, fromNativeError } from './errors.js';
