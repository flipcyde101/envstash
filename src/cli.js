import fs from 'node:fs';
import { EnvstashError } from './crypto.js';
import {
  DEFAULT_VAULT_DIR,
  applyProfile,
  listProfiles,
  resolvePassphrase,
  resolveVaultDir,
  saveProfile,
  stripWorktreeSecrets,
} from './vault.js';

const pkgUrl = new URL('../package.json', import.meta.url);
const pkg = JSON.parse(fs.readFileSync(pkgUrl, 'utf8'));

export const VERSION = pkg.version;

export const HELP_TEXT = `envstash v${VERSION}
Encrypted local .env / .dev.vars profile vault for ephemeral worktrees (scrypt + AES-256-GCM).

Usage:
  envstash save <profile> --from <envFile> [--vault-dir <dir>] [--key-file <path>] [--json]
  envstash ls [--vault-dir <dir>] [--json]
  envstash apply <profile> [--to <targetFile>] [--repo-dir <dir>] [--force-unignored] [--vault-dir <dir>] [--key-file <path>] [--json]
  envstash strip [--file <targetFile>] [--repo-dir <dir>] [--json]
  envstash --help | --version

Environment Variables:
  ENVSTASH_KEY     Encryption passphrase (alternative to --key-file)
  ENVSTASH_VAULT   Vault directory override (default: ${DEFAULT_VAULT_DIR})

Exit Codes:
  0  Success
  1  Invalid CLI usage
  2  Security refusal, missing/wrong key, or vault error
`;

export function parseCliArgs(argv) {
  const positional = [];
  const flags = {
    from: null,
    to: null,
    file: null,
    repoDir: null,
    vaultDir: null,
    keyFile: null,
    forceUnignored: false,
    json: false,
    help: false,
    version: false,
  };

  function readValue(optName, idx) {
    const next = argv[idx + 1];
    if (!next || next.startsWith('-')) {
      throw new Error(`Option ${optName} requires a value`);
    }
    return next;
  }

  try {
    for (let i = 0; i < argv.length; i += 1) {
      const arg = argv[i];
      if (arg === '-h' || arg === '--help') {
        flags.help = true;
      } else if (arg === '-v' || arg === '--version') {
        flags.version = true;
      } else if (arg === '--json') {
        flags.json = true;
      } else if (arg === '--force-unignored') {
        flags.forceUnignored = true;
      } else if (arg === '--from') {
        flags.from = readValue('--from', i);
        i += 1;
      } else if (arg.startsWith('--from=')) {
        flags.from = arg.slice('--from='.length);
      } else if (arg === '--to') {
        flags.to = readValue('--to', i);
        i += 1;
      } else if (arg.startsWith('--to=')) {
        flags.to = arg.slice('--to='.length);
      } else if (arg === '--file') {
        flags.file = readValue('--file', i);
        i += 1;
      } else if (arg.startsWith('--file=')) {
        flags.file = arg.slice('--file='.length);
      } else if (arg === '--repo-dir') {
        flags.repoDir = readValue('--repo-dir', i);
        i += 1;
      } else if (arg.startsWith('--repo-dir=')) {
        flags.repoDir = arg.slice('--repo-dir='.length);
      } else if (arg === '--vault-dir') {
        flags.vaultDir = readValue('--vault-dir', i);
        i += 1;
      } else if (arg.startsWith('--vault-dir=')) {
        flags.vaultDir = arg.slice('--vault-dir='.length);
      } else if (arg === '--key-file') {
        flags.keyFile = readValue('--key-file', i);
        i += 1;
      } else if (arg.startsWith('--key-file=')) {
        flags.keyFile = arg.slice('--key-file='.length);
      } else if (arg.startsWith('-')) {
        return { error: `Unknown option: ${arg}` };
      } else {
        positional.push(arg);
      }
    }
  } catch (err) {
    return { error: err.message };
  }

  return { positional, flags };
}

export async function runCli(argv, io = {}) {
  const stdout = io.stdout ?? ((msg) => process.stdout.write(`${msg}\n`));
  const stderr = io.stderr ?? ((msg) => process.stderr.write(`${msg}\n`));
  const env = io.env ?? process.env;

  const parsed = parseCliArgs(argv);
  if (parsed.error) {
    stderr(`Error: ${parsed.error}\nRun "envstash --help" for usage.`);
    return 1;
  }

  const { positional, flags } = parsed;

  if (flags.version) {
    stdout(VERSION);
    return 0;
  }

  if (flags.help || positional.length === 0) {
    stdout(HELP_TEXT.trimEnd());
    return 0;
  }

  const cmd = positional[0];
  const vaultDir = resolveVaultDir({ vaultDir: flags.vaultDir }, env);

  try {
    if (cmd === 'save') {
      const profile = positional[1];
      if (!profile) {
        stderr('Error: Missing <profile> argument for "envstash save".');
        return 1;
      }
      if (!flags.from) {
        stderr('Error: Missing required --from <envFile> option for "envstash save".');
        return 1;
      }
      const passphrase = resolvePassphrase({ keyFile: flags.keyFile }, env);
      const res = saveProfile({
        profile,
        fromFile: flags.from,
        vaultDir,
        passphrase,
      });
      if (flags.json) {
        stdout(JSON.stringify(res, null, 2));
      } else {
        stdout(
          `Saved profile "${res.profile}" (${res.keyCount} key(s), source: ${res.sourceFileName})`
        );
      }
      return 0;
    }

    if (cmd === 'ls') {
      const res = listProfiles({ vaultDir });
      if (flags.json) {
        stdout(JSON.stringify(res, null, 2));
      } else if (res.profiles.length === 0) {
        stdout(`No saved profiles in ${res.vaultDir}`);
      } else {
        for (const p of res.profiles) {
          stdout(
            `${p.profile}\tkeys=${p.keyCount}\tsource=${p.sourceFileName}\tupdated=${p.updatedAt}`
          );
        }
      }
      return 0;
    }

    if (cmd === 'apply') {
      const profile = positional[1];
      if (!profile) {
        stderr('Error: Missing <profile> argument for "envstash apply".');
        return 1;
      }
      const passphrase = resolvePassphrase({ keyFile: flags.keyFile }, env);
      const res = applyProfile({
        profile,
        toFile: flags.to,
        repoDir: flags.repoDir,
        forceUnignored: flags.forceUnignored,
        vaultDir,
        passphrase,
      });
      if (flags.json) {
        stdout(JSON.stringify(res, null, 2));
      } else {
        stdout(`Applied profile "${res.profile}" (${res.keyCount} key(s)) -> ${res.targetFile}`);
      }
      return 0;
    }

    if (cmd === 'strip') {
      const res = stripWorktreeSecrets({
        file: flags.file,
        repoDir: flags.repoDir,
      });
      if (flags.json) {
        stdout(JSON.stringify(res, null, 2));
      } else if (res.removed.length === 0) {
        stdout('No secret files found to strip.');
      } else {
        stdout(`Stripped ${res.removed.length} file(s): ${res.removed.join(', ')}`);
      }
      return 0;
    }

    stderr(`Error: Unknown command "${cmd}". Expected save, ls, apply, or strip.`);
    return 1;
  } catch (err) {
    if (err instanceof EnvstashError) {
      if (flags.json) {
        stderr(JSON.stringify({ ok: false, code: err.code, error: err.message }, null, 2));
      } else {
        stderr(`Error [${err.code}]: ${err.message}`);
      }
      return err.exitCode;
    }
    stderr(`Unexpected error: ${err.message}`);
    return 2;
  }
}
