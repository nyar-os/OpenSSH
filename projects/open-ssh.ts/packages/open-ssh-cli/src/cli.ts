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

import { AppError, fromNativeError, invokeCapability, exec, transfer as transferFiles, capabilities, configureAudit, auditQuery, runGui, version, type CapabilityItem, type ExecPreview, type ExecResult, type TransferDirection, type TransferPreview, type TransferResult, type Transport } from '@wae/open-ssh';

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

function requiredOption(options: ParsedOptions, key: string): string {
    const value = stringOption(options, key);
    if (value === undefined) {
        throw new AppError({ code: 'invalid_argument', message: `\`--${key}\` is required` });
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
        case 'path_rejected':
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

/**
 * Resolve `--identity` and `--password-env` into exactly one auth path.
 *
 * The password is read from the environment so it never appears in the process
 * command line, in audit params, or in shell history.
 */
function credentials(options: ParsedOptions): { identityPath?: string; password?: string } {
    const identityPath = stringOption(options, 'identity');
    const envName = stringOption(options, 'password-env');
    if ((identityPath === undefined) === (envName === undefined)) {
        throw new AppError({
            code: 'invalid_argument',
            message: 'pass exactly one of `--identity` or `--password-env`',
        });
    }
    if (envName === undefined) return { identityPath };
    const password = process.env[envName];
    if (password === undefined || password === '') {
        throw new AppError({ code: 'invalid_argument', message: `\`--password-env ${envName}\` is not set` });
    }
    return { password };
}

function formatPreview(preview: ExecPreview, host: string): string {
    return [
        'dry-run: no connection opened, no command run',
        `transport\t${preview.transport}`,
        `target\t${preview.user}@${host}:${preview.port}`,
        `auth\t${preview.authMethod}`,
        `host-key\t${preview.hostKeySha256}`,
        `command\t${preview.commandBytes} bytes`,
        `timeout\t${preview.timeoutMs} ms`,
    ].join('\n');
}

/** Write captured output as-is, then the summary on stderr. */
function writeExecResult(result: ExecResult, host: string, ctx: CommandContext): void {
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    ctx.stderr(
        `exec: exit ${result.exitCode ?? 'unknown'} · ${result.stdoutBytes} stdout bytes · ${result.stderrBytes} stderr bytes · ` +
            `${result.durationMs} ms · ${result.user}@${host}:${result.port} over ${result.transport}`,
    );
}

function formatTransferPreview(preview: TransferPreview, host: string): string {
    const lines = [
        'dry-run: no connection opened, no bytes moved',
        `transport\t${preview.transport}`,
        `target\t${preview.user}@${host}:${preview.port}`,
        `auth\t${preview.authMethod}`,
        `host-key\t${preview.hostKeySha256}`,
        `direction\t${preview.direction}`,
        `remote\t${preview.remotePath}`,
        `resume\t${preview.resume ? 'yes' : 'no'}`,
        `timeout\t${preview.timeoutMs} ms`,
    ];
    if (preview.localPath !== null) lines.push(`local\t${preview.localPath}`);
    if (preview.plannedBytes !== null) lines.push(`planned\t${preview.plannedBytes} bytes`);
    return lines.join('\n');
}

/** Write a listing on stdout and the exact counters on stderr. */
function writeTransferResult(result: TransferResult, host: string, ctx: CommandContext): void {
    if (result.direction === 'list') {
        const lines = result.entries.map((entry) => (entry.isDir ? `${entry.name}\tdir` : `${entry.name}\t${entry.size} bytes`));
        if (lines.length) ctx.stdout(lines.join('\n'));
    }
    const summary = result.direction === 'list'
        ? `transfer: ${result.entries.length} entries · ${result.durationMs} ms · ${result.user}@${host}:${result.port} over ${result.transport}`
        : `transfer: ${result.bytes} bytes${result.resumedFrom ? ` (resumed at ${result.resumedFrom})` : ''} · ${result.durationMs} ms · ${result.user}@${host}:${result.port} over ${result.transport}`;
    ctx.stderr(summary);
}

function directionOption(options: ParsedOptions): TransferDirection {
    const raw = requiredOption(options, 'direction');
    if (raw !== 'upload' && raw !== 'download' && raw !== 'list') {
        throw new AppError({ code: 'invalid_argument', message: '`--direction` must be `upload`, `download`, or `list`' });
    }
    return raw;
}

cli.command('exec', 'cli.cmd.exec')
    .option('--transport <transport>', 'cli.opt.transport', { enum: ['ssh', 'rdp'] })
    .option('--host <host>', 'cli.opt.host')
    .option('--port <n>', 'cli.opt.port')
    .option('--user <user>', 'cli.opt.user')
    .option('--command <text>', 'cli.opt.command')
    .option('--identity <path>', 'cli.opt.identity')
    .option('--password-env <name>', 'cli.opt.password-env')
    .option('--host-key-sha256 <pin>', 'cli.opt.host-key-sha256')
    .option('--timeout-ms <n>', 'cli.opt.timeout-ms')
    .option('--dry-run', 'cli.opt.dry-run')
    .actionCtx(async (options, _args, ctx) => {
        try {
            bootstrap(options);
            const host = requiredOption(options, 'host');
            const request = {
                transport: transportOption(options, true),
                host,
                port: integerOption(options, 'port') ?? 22,
                user: requiredOption(options, 'user'),
                command: requiredOption(options, 'command'),
                ...credentials(options),
                hostKeySha256: stringOption(options, 'host-key-sha256'),
                timeoutMs: integerOption(options, 'timeout-ms'),
            };
            if (flag(options, 'dry-run')) {
                const preview = exec({ ...request, dryRun: true });
                emit(options, ctx, preview, formatPreview(preview, host));
                return EXIT.OK;
            }
            const result = exec(request);
            if (flag(options, 'json')) {
                emit(options, ctx, result, '');
            }
            else {
                writeExecResult(result, host, ctx);
            }
            // The remote status decides success, and the exact value stays in
            // `exitCode`. No exit status means the call cannot be called a success.
            return result.exitCode === 0 ? EXIT.OK : EXIT.FAILURE;
        }
        catch (error) {
            return fail(options, ctx, error);
        }
    });

cli.command('transfer', 'cli.cmd.transfer')
    .option('--transport <transport>', 'cli.opt.transport', { enum: ['ssh', 'rdp'] })
    .option('--direction <direction>', 'cli.opt.direction', { enum: ['upload', 'download', 'list'] })
    .option('--host <host>', 'cli.opt.host')
    .option('--port <n>', 'cli.opt.port')
    .option('--user <user>', 'cli.opt.user')
    .option('--local <path>', 'cli.opt.local')
    .option('--remote <path>', 'cli.opt.remote')
    .option('--identity <path>', 'cli.opt.identity')
    .option('--password-env <name>', 'cli.opt.password-env')
    .option('--host-key-sha256 <pin>', 'cli.opt.host-key-sha256')
    .option('--timeout-ms <n>', 'cli.opt.timeout-ms')
    .option('--resume', 'cli.opt.resume')
    .option('--progress', 'cli.opt.progress')
    .option('--dry-run', 'cli.opt.dry-run')
    .actionCtx(async (options, _args, ctx) => {
        try {
            bootstrap(options);
            const host = requiredOption(options, 'host');
            const request = {
                transport: transportOption(options, true),
                host,
                port: integerOption(options, 'port') ?? 22,
                user: requiredOption(options, 'user'),
                direction: directionOption(options),
                remotePath: requiredOption(options, 'remote'),
                localPath: stringOption(options, 'local'),
                ...credentials(options),
                hostKeySha256: stringOption(options, 'host-key-sha256'),
                timeoutMs: integerOption(options, 'timeout-ms'),
                resume: flag(options, 'resume'),
                progress: flag(options, 'progress'),
            };
            if (flag(options, 'dry-run')) {
                const preview = transferFiles({ ...request, dryRun: true });
                emit(options, ctx, preview, formatTransferPreview(preview, host));
                return EXIT.OK;
            }
            const result = transferFiles(request);
            if (flag(options, 'json')) {
                emit(options, ctx, result, '');
            }
            else {
                writeTransferResult(result, host, ctx);
            }
            return EXIT.OK;
        }
        catch (error) {
            return fail(options, ctx, error);
        }
    });

for (const [id, requiredTransport, mutating] of [
    ['connect', true, false],
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
