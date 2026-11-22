import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { EnvstashError, decryptBuffer, encryptBuffer, extractEnvKeys } from './crypto.js';

export const DEFAULT_VAULT_DIR =
  process.platform === 'win32'
    ? 'D:\\Codex\\Projects\\.cache\\envstash'
    : path.join(os.homedir(), '.cache', 'envstash');

const PROFILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function validateProfileName(profile) {
  if (typeof profile !== 'string' || !PROFILE_NAME_RE.test(profile) || profile.includes('..')) {
    throw new EnvstashError(
      `Invalid profile name "${String(profile)}". Use alphanumeric characters, dots, underscores, or hyphens.`,
      'INVALID_PROFILE',
      2
    );
  }
  return profile;
}

export function resolveVaultDir(options = {}, env = process.env) {
  const raw = options.vaultDir || env.ENVSTASH_VAULT || DEFAULT_VAULT_DIR;
  return path.resolve(raw);
}

export function resolvePassphrase(options = {}, env = process.env) {
  if (options.keyFile) {
    const keyPath = path.resolve(options.keyFile);
    if (!fs.existsSync(keyPath) || !fs.statSync(keyPath).isFile()) {
      throw new EnvstashError(`Key file not found: ${keyPath}`, 'KEY_FILE_NOT_FOUND', 2);
    }
    const content = fs.readFileSync(keyPath, 'utf8').replace(/[\r\n]+$/, '');
    if (!content) {
      throw new EnvstashError(`Key file is empty: ${keyPath}`, 'EMPTY_KEY', 2);
    }
    return content;
  }

  if (typeof env.ENVSTASH_KEY === 'string' && env.ENVSTASH_KEY.length > 0) {
    return env.ENVSTASH_KEY;
  }

  throw new EnvstashError(
    'Missing passphrase: set ENVSTASH_KEY or pass --key-file <path>',
    'MISSING_KEY',
    2
  );
}

function getProfileFilePath(vaultDir, profile) {
  validateProfileName(profile);
  return path.join(vaultDir, `${profile}.json`);
}

function globRuleToRegex(pattern) {
  let pat = pattern;
  if (pat.endsWith('/')) {
    return null; // Directory-only rule cannot directly match a plain env file unless parent dir
  }
  const anchored = pat.startsWith('/');
  if (anchored) pat = pat.slice(1);

  let escaped = '';
  for (let i = 0; i < pat.length; i += 1) {
    const ch = pat[i];
    if (ch === '*' && pat[i + 1] === '*') {
      escaped += '.*';
      i += 1;
    } else if (ch === '*') {
      escaped += '[^/]*';
    } else if (ch === '?') {
      escaped += '[^/]';
    } else if ('+^$().|[]{}!\\'.includes(ch)) {
      escaped += `\\${ch}`;
    } else {
      escaped += ch;
    }
  }

  const prefix = anchored || pat.includes('/') ? '^' : '(?:^|.*/)';
  return new RegExp(`${prefix}${escaped}(?:$|/.*)`);
}

export function isIgnoredByGitignoreFile(gitignorePath, relTargetPath) {
  if (!fs.existsSync(gitignorePath)) return false;
  const content = fs.readFileSync(gitignorePath, 'utf8');
  const norm = relTargetPath.replace(/\\/g, '/').replace(/^\/+/, '');
  let ignored = false;

  for (const rawLine of content.replace(/\r\n/g, '\n').split('\n')) {
    const line = rawLine.replace(/\s+$/, '');
    if (!line || line.startsWith('#')) continue;
    let negated = false;
    let rule = line;
    if (rule.startsWith('!')) {
      negated = true;
      rule = rule.slice(1);
    } else if (rule.startsWith('\\#') || rule.startsWith('\\!')) {
      rule = rule.slice(1);
    }
    if (!rule) continue;
    const rx = globRuleToRegex(rule);
    if (rx && rx.test(norm)) {
      ignored = !negated;
    }
  }
  return ignored;
}

export function verifyTargetGitIgnored(targetPath, repoDir) {
  const absRepo = path.resolve(repoDir || '.');
  const absTarget = path.resolve(absRepo, targetPath);
  const workDir = fs.existsSync(absRepo) ? absRepo : path.dirname(absTarget);

  if (fs.existsSync(workDir)) {
    const revParse = spawnSync('git', ['-C', workDir, 'rev-parse', '--is-inside-work-tree'], {
      encoding: 'utf8',
      windowsHide: true,
    });

    if (revParse.status === 0 && revParse.stdout.trim() === 'true') {
      const topLevelRes = spawnSync('git', ['-C', workDir, 'rev-parse', '--show-toplevel'], {
        encoding: 'utf8',
        windowsHide: true,
      });
      const gitRoot =
        topLevelRes.status === 0 && topLevelRes.stdout.trim()
          ? path.resolve(topLevelRes.stdout.trim())
          : workDir;

      const relToGitRoot = path.relative(gitRoot, absTarget).replace(/\\/g, '/');
      if (!relToGitRoot.startsWith('..')) {
        const trackedCheck = spawnSync(
          'git',
          ['-C', gitRoot, 'ls-files', '--error-unmatch', '--', relToGitRoot],
          { encoding: 'utf8', windowsHide: true }
        );
        if (trackedCheck.status === 0) {
          return {
            ignored: false,
            method: 'git-ls-files',
            reason: `"${relToGitRoot}" is already tracked by git`,
          };
        }

        const ignoreCheck = spawnSync(
          'git',
          ['-C', gitRoot, 'check-ignore', '-q', '--', relToGitRoot],
          { encoding: 'utf8', windowsHide: true }
        );
        if (ignoreCheck.status === 0) {
          return { ignored: true, method: 'git-check-ignore' };
        }
        if (ignoreCheck.status === 1) {
          return {
            ignored: false,
            method: 'git-check-ignore',
            reason: `"${relToGitRoot}" is not ignored by git (add it to .gitignore before applying secrets)`,
          };
        }
      }
    }
  }

  // Fallback for non-git directories: inspect .gitignore in repoDir
  const relToRepo = path.relative(absRepo, absTarget).replace(/\\/g, '/');
  const gitignorePath = path.join(absRepo, '.gitignore');
  if (!relToRepo.startsWith('..') && isIgnoredByGitignoreFile(gitignorePath, relToRepo)) {
    return { ignored: true, method: 'gitignore-rule' };
  }

  return {
    ignored: false,
    method: 'gitignore-rule',
    reason: `"${path.basename(absTarget)}" is not excluded by git or .gitignore in ${absRepo}`,
  };
}

export function saveProfile({ profile, fromFile, vaultDir, passphrase }) {
  validateProfileName(profile);
  const absFrom = path.resolve(fromFile);
  if (!fs.existsSync(absFrom) || !fs.statSync(absFrom).isFile()) {
    throw new EnvstashError(`Source env file does not exist: ${absFrom}`, 'SOURCE_NOT_FOUND', 2);
  }

  const plaintextBuf = fs.readFileSync(absFrom);
  const keys = extractEnvKeys(plaintextBuf);
  const encrypted = encryptBuffer(plaintextBuf, passphrase, profile);
  plaintextBuf.fill(0);

  fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  const vaultFile = getProfileFilePath(vaultDir, profile);

  const now = new Date().toISOString();
  let createdAt = now;
  if (fs.existsSync(vaultFile)) {
    try {
      const prev = JSON.parse(fs.readFileSync(vaultFile, 'utf8'));
      if (typeof prev.createdAt === 'string') createdAt = prev.createdAt;
    } catch {
      // Overwrite corrupted metadata timestamp with current timestamp
    }
  }

  const record = {
    version: 1,
    profile,
    sourceFileName: path.basename(absFrom),
    keyCount: keys.length,
    createdAt,
    updatedAt: now,
    ...encrypted,
  };

  fs.writeFileSync(vaultFile, `${JSON.stringify(record, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });

  return {
    ok: true,
    profile,
    keyCount: keys.length,
    sourceFileName: record.sourceFileName,
    vaultFile,
    createdAt,
    updatedAt: now,
  };
}

export function listProfiles({ vaultDir }) {
  if (!fs.existsSync(vaultDir)) {
    return { ok: true, vaultDir, profiles: [] };
  }

  const entries = fs.readdirSync(vaultDir, { withFileTypes: true });
  const profiles = [];

  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
    const full = path.join(vaultDir, entry.name);
    try {
      const raw = JSON.parse(fs.readFileSync(full, 'utf8'));
      profiles.push({
        profile: raw.profile ?? entry.name.slice(0, -5),
        keyCount: Number.isInteger(raw.keyCount) ? raw.keyCount : 0,
        sourceFileName: raw.sourceFileName ?? '.env',
        createdAt: raw.createdAt ?? null,
        updatedAt: raw.updatedAt ?? null,
      });
    } catch {
      // Ignore unreadable non-profile files
    }
  }

  profiles.sort((a, b) => a.profile.localeCompare(b.profile));
  return { ok: true, vaultDir, profiles };
}

export function applyProfile({
  profile,
  toFile,
  repoDir,
  forceUnignored = false,
  vaultDir,
  passphrase,
}) {
  validateProfileName(profile);
  const vaultFile = getProfileFilePath(vaultDir, profile);
  if (!fs.existsSync(vaultFile) || !fs.statSync(vaultFile).isFile()) {
    throw new EnvstashError(`Saved profile "${profile}" not found in vault`, 'PROFILE_NOT_FOUND', 2);
  }

  let record;
  try {
    record = JSON.parse(fs.readFileSync(vaultFile, 'utf8'));
  } catch {
    throw new EnvstashError(`Vault profile "${profile}" contains invalid JSON`, 'CORRUPT_VAULT', 2);
  }

  const absRepo = path.resolve(repoDir || '.');
  if (!fs.existsSync(absRepo) || !fs.statSync(absRepo).isDirectory()) {
    throw new EnvstashError(`Repository directory does not exist: ${absRepo}`, 'REPO_NOT_FOUND', 2);
  }

  const defaultTargetName =
    record.sourceFileName === '.dev.vars' || record.sourceFileName === '.env'
      ? record.sourceFileName
      : '.env';
  const chosenTarget = toFile || defaultTargetName;
  const absTarget = path.isAbsolute(chosenTarget)
    ? path.normalize(chosenTarget)
    : path.resolve(absRepo, chosenTarget);

  // Verify git ignore status BEFORE decrypting or writing any plaintext bytes to disk!
  const ignoreCheck = verifyTargetGitIgnored(absTarget, absRepo);
  if (!ignoreCheck.ignored && !forceUnignored) {
    throw new EnvstashError(
      `Refusing to write plaintext secrets: ${ignoreCheck.reason}. Pass --force-unignored to override.`,
      'TARGET_UNIGNORED',
      2
    );
  }

  const plaintextBuf = decryptBuffer(record, passphrase, profile);
  try {
    fs.mkdirSync(path.dirname(absTarget), { recursive: true });
    fs.writeFileSync(absTarget, plaintextBuf, { mode: 0o600 });
  } finally {
    plaintextBuf.fill(0);
  }

  return {
    ok: true,
    profile,
    targetFile: absTarget,
    keyCount: record.keyCount ?? 0,
    ignored: ignoreCheck.ignored,
    forcedUnignored: Boolean(!ignoreCheck.ignored && forceUnignored),
  };
}

function secureWipeAndUnlink(filePath) {
  const lstat = fs.lstatSync(filePath);
  if (lstat.isSymbolicLink()) {
    fs.unlinkSync(filePath);
    return;
  }
  if (!lstat.isFile()) {
    throw new EnvstashError(`Target is not a regular file: ${filePath}`, 'INVALID_STRIP_TARGET', 2);
  }

  const size = lstat.size;
  if (size > 0) {
    const fd = fs.openSync(filePath, 'r+');
    try {
      const chunkSize = Math.min(size, 64 * 1024);
      let offset = 0;
      while (offset < size) {
        const len = Math.min(chunkSize, size - offset);
        const rnd = crypto.randomBytes(len);
        fs.writeSync(fd, rnd, 0, len, offset);
        offset += len;
      }
      fs.fsyncSync(fd);

      const zeroBuf = Buffer.alloc(chunkSize, 0);
      offset = 0;
      while (offset < size) {
        const len = Math.min(chunkSize, size - offset);
        fs.writeSync(fd, zeroBuf, 0, len, offset);
        offset += len;
      }
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }
  fs.unlinkSync(filePath);
}

export function stripWorktreeSecrets({ file, repoDir }) {
  const absRepo = path.resolve(repoDir || '.');
  const candidates = file
    ? [path.isAbsolute(file) ? path.normalize(file) : path.resolve(absRepo, file)]
    : [path.join(absRepo, '.env'), path.join(absRepo, '.dev.vars')];

  const removed = [];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      secureWipeAndUnlink(candidate);
      removed.push(candidate);
    }
  }

  return {
    ok: true,
    repoDir: absRepo,
    removed,
  };
}
