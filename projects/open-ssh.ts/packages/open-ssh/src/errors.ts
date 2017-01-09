/**
 * Structured error shape shared by the native boundary, the CLI, and the GUI.
 *
 * The N-API boundary throws `Error` with a `wae.error:<json>` payload. This
 * module converts that into `AppError` without inventing a second schema.
 */

/** Error payload emitted by the native boundary. */
export interface ErrorPayload {
    code: string;
    capability?: string;
    platform?: string;
    message: string;
}

/** Error thrown by the typed library, the CLI, and the GUI adapter. */
export class AppError extends Error {
    readonly code: string;
    readonly capability?: string;
    readonly platform?: string;

    constructor(payload: ErrorPayload) {
        super(payload.message);
        this.name = 'AppError';
        this.code = payload.code;
        this.capability = payload.capability;
        this.platform = payload.platform;
    }

    /** Machine-readable form. */
    toJSON(): ErrorPayload {
        return {
            code: this.code,
            ...(this.capability ? { capability: this.capability } : {}),
            ...(this.platform ? { platform: this.platform } : {}),
            message: this.message,
        };
    }
}

/** Prefix used by the native boundary when it throws a structured error. */
export const NATIVE_ERROR_PREFIX = 'wae.error:';

/** Whether the value is already an `AppError`. */
export function isAppError(value: unknown): value is AppError {
    return value instanceof AppError;
}

/**
 * Normalize an exception from the native boundary or the filesystem.
 *
 * The native boundary is authoritative. When it sends `wae.error:<json>`, the
 * payload is used as-is. Other exceptions become `native_unavailable` or
 * `internal_error` with a stable code so agents do not parse prose.
 */
export function fromNativeError(value: unknown): AppError {
    if (value instanceof AppError) return value;
    const message = value instanceof Error ? value.message : String(value);
    const index = message.indexOf(NATIVE_ERROR_PREFIX);
    if (index >= 0) {
        try {
            const payload = JSON.parse(message.slice(index + NATIVE_ERROR_PREFIX.length)) as Partial<ErrorPayload>;
            if (typeof payload.message === 'string' && typeof payload.code === 'string') {
                return new AppError({
                    code: payload.code,
                    ...(typeof payload.capability === 'string' ? { capability: payload.capability } : {}),
                    ...(typeof payload.platform === 'string' ? { platform: payload.platform } : {}),
                    message: payload.message,
                });
            }
        }
        catch {
            // Fall through to the generic error below.
        }
    }
    const lower = message.toLowerCase();
    if (lower.includes('cannot find module') || lower.includes('no native binding')) {
        return new AppError({
            code: 'native_unavailable',
            message:
                `${message}\nRun \`pnpm run build:napi\` from the repository root, ` +
                'or install the matching platform package.',
        });
    }
    return new AppError({ code: 'internal_error', message });
}
