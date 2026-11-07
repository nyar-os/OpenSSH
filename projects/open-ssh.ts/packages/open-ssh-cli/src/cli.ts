#!/usr/bin/env node
/**
 * Agent-facing CLI entry.
 *
 * Contract:
 * - non-interactive, always exits with a stable code
 * - `--json` returns `{ ok, data }` or `{ ok: false, error }` under `wae.cli-result/v0`
 * - capability ids are transport-neutral, `--transport` selects the adapter
 * - every mutating command supports `--dry-run`
 * - every command configures the audit actor before calling the native layer
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createCli, type CommandContext, type ParsedOptions } from '@wae/commander';

import { AppError, fromNativeError, invokeCapability, capabilities, configureAudit, auditQuery, runGui, version, type CapabilityItem, type Transport } from '@wae/open-ssh';

import { loadRuntimeContract, type ActorChannel } from './runtime.js';

const ENVELOPE_SCHEMA = 'wae.cli-result/v0';

const EXIT = { OK: 0, FAILURE: 1, USAGE: 2, CAPABILITY: 3, CANCELED: 4 } as const;

const here = path.dirname(fileURLToPath(import.meta.url));
const localesDir = path.join(here, '..', 'locales');

const cli = createCli('open-ssh')
    .locales(localesDir)
    .intro('cli.intro')
    // Root options take no `OptionConfig` in `@wae/commander`. Defaults and
    // enum validation live in `bootstrap()` so the help tree stays stable.
    .option('--actor <id>', 'cli.opt.actor')
    .option('--actor-kind <kind>', 'cli.opt.actor-kind')
    .option('--actor-source <source>', 'cli.opt.actor-source')
    .option('--json', 'cli.opt.json');

function stringOption(options: ParsedOptions, key: string): string | undefined {
    const value = options[key];
    return typeof value === 'string' && value.trim() ? value : undefined;
}

function flag(options: ParsedOptions, key: string): boolean {
    return options[key] === true;
}

function integerOption(options: ParsedOptions, key: string): number | undefined {
    const raw = stringOption(options, key);
    if (raw === undefined) return undefined;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < 0) {
        throw new AppError({ code: 'invalid_argument', message: `\`--${key}\` must be a non-negative integer` });
    }
    return value;
}

/** Resolve `--transport`, rejecting values the product does not know. */
function transportOption(options: ParsedOptions, required: boolean): Transport | undefined {
    const raw = stringOption(options, 'transport');
    if (raw === undefined) {
        if (required) throw new AppError({ code: 'invalid_argument', message: '`--transport` is required for this capability' });
        return undefined;
    }
    if (raw !== 'ssh' && raw !== 'rdp') {
        throw new AppError({ code: 'invalid_argument', message: '`--transport` must be `ssh` or `rdp`' });
    }
    return raw;
}

const runtime = loadRuntimeContract();

/**
 * Resolve one actor field from the channel declared in `audit.actor`.
 *
 * `flag` and `env` are the CLI's own inputs, `host` is the CLI default, and
 * `session` only exists in the GUI host, so the CLI falls back to `host`.
 */
function actorValue(
    channel: ActorChannel | undefined,
    fromFlag: string | undefined,
    envKey: string,
    hostDefault: string,
): string {
    switch (channel) {
        case 'env':
            return process.env[envKey]?.trim() || hostDefault;
        case 'host':
            return hostDefault;
        case 'session':
            return hostDefault;
        case 'flag':
        default:
            return fromFlag ?? hostDefault;
    }
}

/** Configure the audit actor before any capability call. */
function bootstrap(options: ParsedOptions): void {
    const mapping = runtime.audit?.actor;
    const kind = actorValue(mapping?.kind, stringOption(options, 'actor-kind'), 'WAE_ACTOR_KIND', 'user');
    if (kind !== 'user' && kind !== 'agent') {
        throw new AppError({ code: 'invalid_argument', message: '`--actor-kind` must be `user` or `agent`' });
    }
    configureAudit({
        actorKind: kind,
        actorId: actorValue(mapping?.id, stringOption(options, 'actor'), 'WAE_ACTOR_ID', 'unknown'),
        actorSource: actorValue(mapping?.source, stringOption(options, 'actor-source'), 'WAE_ACTOR_SOURCE', 'cli'),
    });
}

function emit(options: ParsedOptions, ctx: CommandContext, data: unknown, human: string): void {
    if (flag(options, 'json')) {
        ctx.stdout(JSON.stringify({ schema: ENVELOPE_SCHEMA, ok: true, data }, null, 2));
        return;
    }
    if (human) ctx.stdout(human);
}

function exitFor(code: string | undefined): number {
    switch (code) {
        case 'unsupported_platform':
        case 'not_implemented':
        case 'dependency_blocked':
            return EXIT.CAPABILITY;
        case 'invalid_argument':
        case 'unknown_command':
            return EXIT.USAGE;
        case 'canceled':
            return EXIT.CANCELED;
        default:
            return EXIT.FAILURE;
    }
}

function fail(options: ParsedOptions, ctx: CommandContext, error: unknown): number {
    const appError = fromNativeError(error);
    if (flag(options, 'json')) {
        ctx.stdout(JSON.stringify({ schema: ENVELOPE_SCHEMA, ok: false, error: appError.toJSON() }, null, 2));
    }
    else {
        ctx.stderr(`${appError.code}: ${appError.message}`);
    }
    return exitFor(appError.code);
}

function formatCapabilities(items: CapabilityItem[], transports: Transport[], notes: string[]): string {
    const header = ['capability', 'state', ...transports].join('\t');
    const rows = items.map((item) => {
        const cells = item.transports.map((row) => (row.state === null ? 'supported' : row.state));
        return [item.id, item.state ?? 'supported', ...cells].join('\t');
    });
    const lines = [header, ...rows];
    if (notes.length) lines.push('', ...notes.map((note) => `note: ${note}`));
    return lines.join('\n');
}

/** Resolve one domain capability. The skeleton refuses before any side effect. */
function resolve(options: ParsedOptions, ctx: CommandContext, capability: string, requiredTransport: boolean, mutating: boolean): number {
    try {
        if (mutating && flag(options, 'dry-run')) {
            // The dry-run flag is part of the contract even while the capability
            // refuses. The plan itself cannot exist before implementation, so the
            // refusal still decides the exit code.
            ctx.stderr('dry-run: plan unavailable because the capability is not implemented');
        }
        bootstrap(options);
        const transport = transportOption(options, requiredTransport);
        const data = invokeCapability(capability, transport);
        emit(options, ctx, data, String(data));
        return EXIT.OK;
    }
    catch (error) {
        return fail(options, ctx, error);
    }
}

cli.command('capabilities', 'cli.cmd.capabilities').actionCtx(async (options, _args, ctx) => {
    try {
        bootstrap(options);
        const report = capabilities();
        emit(options, ctx, report, formatCapabilities(report.items, report.transports, report.notes));
        return EXIT.OK;
    }
    catch (error) {
        return fail(options, ctx, error);
    }
});

cli.command('version', 'cli.cmd.version').actionCtx(async (options, _args, ctx) => {
    try {
        bootstrap(options);
        const current = version();
        emit(options, ctx, { version: current }, current);
        return EXIT.OK;
    }
    catch (error) {
        return fail(options, ctx, error);
    }
});

cli.command('audit', 'cli.cmd.audit')
    .option('--kind <kind>', 'cli.opt.kind', { enum: ['user', 'agent'] })
    .option('--id <id>', 'cli.opt.id')
    .option('--capability <name>', 'cli.opt.capability')
    .option('--from-ms <n>', 'cli.opt.from-ms')
    .option('--to-ms <n>', 'cli.opt.to-ms')
    .option('--limit <n>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        try {
            bootstrap(options);
            const entries = auditQuery({
                kind: stringOption(options, 'kind') === 'agent' ? 'agent' : stringOption(options, 'kind') === 'user' ? 'user' : undefined,
                id: stringOption(options, 'id'),
                capability: stringOption(options, 'capability'),
                fromMs: integerOption(options, 'from-ms'),
                toMs: integerOption(options, 'to-ms'),
                limit: integerOption(options, 'limit'),
            });
            emit(options, ctx, entries, JSON.stringify(entries, null, 2));
            return EXIT.OK;
        }
        catch (error) {
            return fail(options, ctx, error);
        }
    });

cli.command('gui', 'cli.cmd.gui')
    .option('--content-dir <path>', 'cli.opt.content-dir')
    .actionCtx(async (options, _args, ctx) => {
        try {
            bootstrap(options);
            const backend = await runGui({ contentDir: stringOption(options, 'content-dir') });
            emit(options, ctx, { backend }, `closed (${backend})`);
            return EXIT.OK;
        }
        catch (error) {
            return fail(options, ctx, error);
        }
    });

for (const [id, requiredTransport, mutating] of [
    ['connect', true, false],
    ['exec', true, false],
    ['transfer', true, true],
    ['session', true, false],
    ['host-inventory', false, false],
    ['port-forward', false, false],
    ['key-management', false, false],
    ['known-hosts', false, true],
    ['credential-store', false, true],
    ['host-install', false, true],
    ['host-uninstall', false, true],
] as const) {
    const command = cli.command(id, `cli.cmd.${id}`).option('--transport <transport>', 'cli.opt.transport', { enum: ['ssh', 'rdp'] });
    if (mutating) command.option('--dry-run', 'cli.opt.dry-run');
    command.actionCtx(async (options, _args, ctx) => resolve(options, ctx, id, requiredTransport, mutating));
}

/** Exported for build tooling, which reads the command tree without running `--help`. */
export { cli };

/** Nearest `package.json` name above a file or directory, if any. */
function nearestPackageName(target: string): string | undefined {
    let dir = path.dirname(target);
    while (true) {
        const manifest = path.join(dir, 'package.json');
        if (fs.existsSync(manifest)) {
            try {
                const parsed = JSON.parse(fs.readFileSync(manifest, 'utf8')) as { name?: unknown };
                return typeof parsed.name === 'string' ? parsed.name : undefined;
            }
            catch {
                return undefined;
            }
        }
        const parent = path.dirname(dir);
        if (parent === dir) return undefined;
        dir = parent;
    }
}

/** True when `invoked` resolves to this module, following package-manager symlinks and junctions. */
function relationToEntry(invoked: string): 'main' | 'imported' | 'unresolved' {
    const self = fileURLToPath(import.meta.url);
    try {
        if (fs.realpathSync(invoked) === fs.realpathSync(self)) return 'main';
    }
    catch {
        // A dangling link or removed file still counts as a launch attempt when
        // it carries this entry's name.
    }
    if (path.basename(invoked) !== path.basename(self)) return 'imported';
    return nearestPackageName(invoked) === nearestPackageName(self) ? 'unresolved' : 'imported';
}

const entry = process.argv[1];
if (entry !== undefined) {
    const relation = relationToEntry(entry);
    if (relation === 'main') {
        process.exitCode = await cli.parse(process.argv);
    }
    else if (relation === 'unresolved') {
        console.error(`[open-ssh] cannot resolve entry "${entry}" to "${fileURLToPath(import.meta.url)}"`);
        process.exitCode = 1;
    }
}
