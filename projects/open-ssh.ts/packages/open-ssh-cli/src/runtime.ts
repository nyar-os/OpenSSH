/**
 * Runtime contract written by `wae build`.
 *
 * `install` and `audit` live in `wae.config.ts`, which is build-time data. The
 * build writes this file next to the compiled CLI entry, so the CLI can apply
 * the same values at runtime without parsing or executing the config.
 */
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

export type ActorChannel = 'flag' | 'env' | 'session' | 'host';

export type RuntimeContract = {
    schema?: string;
    install?: { shortcutDefault?: boolean };
    audit?: { actor?: { kind?: ActorChannel; id?: ActorChannel; source?: ActorChannel } };
};

const CONTRACT_URL = new URL('./wae-runtime.json', import.meta.url);

/** Read the contract if the build wrote one; absent means "use CLI defaults". */
export function loadRuntimeContract(): RuntimeContract {
    try {
        const raw = fs.readFileSync(fileURLToPath(CONTRACT_URL), 'utf8');
        const value: unknown = JSON.parse(raw);
        if (typeof value !== 'object' || value === null || Array.isArray(value)) return {};
        return value as RuntimeContract;
    }
    catch {
        return {};
    }
}
