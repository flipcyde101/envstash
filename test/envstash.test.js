import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runCli, VERSION } from '../src/cli.js';
import { DEFAULT_VAULT_DIR } from '../src/vault.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const BIN_PATH = path.join(REPO_ROOT, 'bin', 'envstash.js');

function makeTempSandbox(t) {
  const baseCache = fs.existsSync('D:\\Codex\\Projects')
    ? path.join('D:\\Codex\\Projects', '.cache')
    : os.tmpdir();
  fs.mkdirSync(baseCache, { recursive: true });
  const root = fs.mkdtempSync(path.join(baseCache, 'envstash-test-'));
  const vaultDir = path.join(root, 'vault');
  const repoDir = path.join(root, 'repo');
  const sourceDir = path.join(root, 'source');
  fs.mkdirSync(repoDir, { recursive: true });
  fs.mkdirSync(sourceDir, { recursive: true });

  execFileSync('git', ['init', '-q'], { cwd: repoDir });

  t.after(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  return { root, vaultDir, repoDir, sourceDir };
}

async function execCli(args, envOverrides = {}) {
  const out = [];
  const err = [];
  const code = await runCli(args, {
    stdout: (m) => out.push(m),
    stderr: (m) => err.push(m),
    env: { ...process.env, ...envOverrides },
  });
  return {
    code,
    stdout: out.join('\n'),
    stderr: err.join('\n'),
  };
}

test('CLI --help, --version, and default vault path work properly', () => {
  const helpOut = execFileSync(process.execPath, [BIN_PATH, '--help'], { encoding: 'utf8' });
  assert.match(helpOut, /envstash save <profile>/);

  const verOut = execFileSync(process.execPath, [BIN_PATH, '--version'], { encoding: 'utf8' });
  assert.equal(verOut.trim(), VERSION);

  if (process.platform === 'win32') {
    assert.equal(DEFAULT_VAULT_DIR, 'D:\\Codex\\Projects\\.cache\\envstash');
  }
});

test('AES-256-GCM roundtrip: save -> ls -> apply -> strip with zero plaintext leak in metadata', async (t) => {
  const { vaultDir, repoDir, sourceDir, root } = makeTempSandbox(t);
  const secretOne = 'sk_live_SUPER_CONFIDENTIAL_99887766';
  const secretTwo = 'postgres://admin:TopSecretPass!@127.0.0.1:5432/prod';
  const originalEnv = `# Worktree secrets\nSTRIPE_SECRET=${secretOne}\nDATABASE_URL=${secretTwo}\nEXPORTED_KEY=abc123\n`;

  const sourceEnvPath = path.join(sourceDir, '.env');
  fs.writeFileSync(sourceEnvPath, originalEnv, 'utf8');

  const keyFile = path.join(root, 'vault.key');
  fs.writeFileSync(keyFile, 'correct-horse-battery-staple-2026\n', 'utf8');

  // Ignore .env and .dev.vars inside the git worktree
  fs.writeFileSync(path.join(repoDir, '.gitignore'), '.env\n.dev.vars\n', 'utf8');

  // 1. Save
  const saveRes = await execCli([
    'save',
    'worker-local',
    '--from',
    sourceEnvPath,
    '--vault-dir',
    vaultDir,
    '--key-file',
    keyFile,
    '--json',
  ]);
  assert.equal(saveRes.code, 0, saveRes.stderr);
  const saveJson = JSON.parse(saveRes.stdout);
  assert.equal(saveJson.keyCount, 3);
  assert.equal(saveJson.profile, 'worker-local');

  // Verify encrypted vault file on disk has 32-byte salt, 12-byte IV, 16-byte authTag, and NO secret values
  const rawVaultText = fs.readFileSync(saveJson.vaultFile, 'utf8');
  assert.ok(!rawVaultText.includes(secretOne), 'Plaintext secret 1 must never appear in vault JSON');
  assert.ok(!rawVaultText.includes(secretTwo), 'Plaintext secret 2 must never appear in vault JSON');
  assert.ok(!rawVaultText.includes('STRIPE_SECRET'), 'Even plaintext env lines must stay encrypted');

  const vaultObj = JSON.parse(rawVaultText);
  assert.equal(Buffer.from(vaultObj.salt, 'base64').length, 32);
  assert.equal(Buffer.from(vaultObj.iv, 'base64').length, 12);
  assert.equal(Buffer.from(vaultObj.authTag, 'base64').length, 16);

  // 2. List
  const lsRes = await execCli(['ls', '--vault-dir', vaultDir, '--json']);
  assert.equal(lsRes.code, 0);
  const lsJson = JSON.parse(lsRes.stdout);
  assert.equal(lsJson.profiles.length, 1);
  assert.equal(lsJson.profiles[0].profile, 'worker-local');
  assert.equal(lsJson.profiles[0].keyCount, 3);
  assert.ok(lsJson.profiles[0].createdAt);
  assert.ok(lsJson.profiles[0].updatedAt);

  // 3. Apply
  const applyRes = await execCli([
    'apply',
    'worker-local',
    '--repo-dir',
    repoDir,
    '--to',
    '.env',
    '--vault-dir',
    vaultDir,
    '--key-file',
    keyFile,
    '--json',
  ]);
  assert.equal(applyRes.code, 0, applyRes.stderr);
  const appliedEnvPath = path.join(repoDir, '.env');
  assert.equal(fs.existsSync(appliedEnvPath), true);
  assert.equal(fs.readFileSync(appliedEnvPath, 'utf8'), originalEnv);

  // 4. Strip
  const stripRes = await execCli(['strip', '--repo-dir', repoDir, '--json']);
  assert.equal(stripRes.code, 0);
  const stripJson = JSON.parse(stripRes.stdout);
  assert.deepEqual(stripJson.removed, [appliedEnvPath]);
  assert.equal(fs.existsSync(appliedEnvPath), false);
});

test('wrong passphrase or tampered auth tag is rejected with exit code 2 (GCM auth failure)', async (t) => {
  const { vaultDir, repoDir, sourceDir } = makeTempSandbox(t);
  const srcVars = path.join(sourceDir, '.dev.vars');
  fs.writeFileSync(srcVars, 'CF_API_TOKEN=secret_value_abc\n', 'utf8');
  fs.writeFileSync(path.join(repoDir, '.gitignore'), '.dev.vars\n', 'utf8');

  const saveRes = await execCli(
    ['save', 'cf-dev', '--from', srcVars, '--vault-dir', vaultDir],
    { ENVSTASH_KEY: 'right-passphrase-123' }
  );
  assert.equal(saveRes.code, 0);

  // Wrong passphrase attempt
  const wrongKeyRes = await execCli(
    ['apply', 'cf-dev', '--repo-dir', repoDir, '--to', '.dev.vars', '--vault-dir', vaultDir, '--json'],
    { ENVSTASH_KEY: 'wrong-passphrase-999' }
  );
  assert.equal(wrongKeyRes.code, 2);
  assert.match(wrongKeyRes.stderr, /AUTH_FAILED/);
  assert.equal(fs.existsSync(path.join(repoDir, '.dev.vars')), false);

  // Tamper with GCM auth tag in vault file and retry with right passphrase
  const vaultFile = path.join(vaultDir, 'cf-dev.json');
  const envelope = JSON.parse(fs.readFileSync(vaultFile, 'utf8'));
  const tagBuf = Buffer.from(envelope.authTag, 'base64');
  tagBuf[0] ^= 0xff;
  envelope.authTag = tagBuf.toString('base64');
  fs.writeFileSync(vaultFile, JSON.stringify(envelope, null, 2), 'utf8');

  const tamperedRes = await execCli(
    ['apply', 'cf-dev', '--repo-dir', repoDir, '--to', '.dev.vars', '--vault-dir', vaultDir],
    { ENVSTASH_KEY: 'right-passphrase-123' }
  );
  assert.equal(tamperedRes.code, 2);
  assert.match(tamperedRes.stderr, /GCM authentication failed/);
  assert.equal(fs.existsSync(path.join(repoDir, '.dev.vars')), false);
});

test('refuses to write unignored .env with exit code 2 before touching disk unless --force-unignored', async (t) => {
  const { vaultDir, repoDir, sourceDir } = makeTempSandbox(t);
  const srcEnv = path.join(sourceDir, '.env');
  fs.writeFileSync(srcEnv, 'SECRET_KEY=never_commit_me\n', 'utf8');

  // Notice: repoDir has NO .gitignore ignoring .env!
  const saveRes = await execCli(
    ['save', 'unignored-test', '--from', srcEnv, '--vault-dir', vaultDir],
    { ENVSTASH_KEY: 'pass-1234' }
  );
  assert.equal(saveRes.code, 0);

  const targetEnv = path.join(repoDir, '.env');
  const refused = await execCli(
    ['apply', 'unignored-test', '--repo-dir', repoDir, '--to', '.env', '--vault-dir', vaultDir, '--json'],
    { ENVSTASH_KEY: 'pass-1234' }
  );
  assert.equal(refused.code, 2);
  assert.match(refused.stderr, /TARGET_UNIGNORED/);
  assert.equal(fs.existsSync(targetEnv), false, 'Must NEVER write plaintext to unignored path');

  // Explicit --force-unignored override succeeds
  const forced = await execCli(
    [
      'apply',
      'unignored-test',
      '--repo-dir',
      repoDir,
      '--to',
      '.env',
      '--force-unignored',
      '--vault-dir',
      vaultDir,
      '--json',
    ],
    { ENVSTASH_KEY: 'pass-1234' }
  );
  assert.equal(forced.code, 0);
  assert.equal(fs.existsSync(targetEnv), true);
  assert.equal(fs.readFileSync(targetEnv, 'utf8'), 'SECRET_KEY=never_commit_me\n');
});

test('repository contains zero U+2014 em dashes across all tracked project files', () => {
  const emDash = String.fromCharCode(0x2014);
  const checked = [];

  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        const content = fs.readFileSync(full, 'utf8');
        assert.equal(
          content.includes(emDash),
          false,
          `Found forbidden U+2014 em dash in ${path.relative(REPO_ROOT, full)}`
        );
        checked.push(full);
      }
    }
  }

  walk(REPO_ROOT);
  assert.ok(checked.length >= 8);
});
