import crypto from 'node:crypto';

const SALT_BYTES = 32;
const IV_BYTES = 12;
const KEY_BYTES = 32;
const AUTH_TAG_BYTES = 16;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

export class EnvstashError extends Error {
  constructor(message, code, exitCode = 2) {
    super(message);
    this.name = 'EnvstashError';
    this.code = code;
    this.exitCode = exitCode;
  }
}

export function extractEnvKeys(content) {
  const text = Buffer.isBuffer(content) ? content.toString('utf8') : String(content);
  const keys = new Set();
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (match) {
      keys.add(match[1]);
    }
  }
  return [...keys];
}

function buildAad(profile) {
  return Buffer.from(`envstash:v1:${profile}`, 'utf8');
}

export function encryptBuffer(plaintextBuf, passphrase, profile) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new EnvstashError('Encryption passphrase cannot be empty', 'MISSING_KEY', 2);
  }
  const salt = crypto.randomBytes(SALT_BYTES);
  const iv = crypto.randomBytes(IV_BYTES);
  const derivedKey = crypto.scryptSync(passphrase, salt, KEY_BYTES, SCRYPT_PARAMS);

  const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv, {
    authTagLength: AUTH_TAG_BYTES,
  });
  cipher.setAAD(buildAad(profile));

  const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();
  derivedKey.fill(0);

  return {
    kdf: 'scrypt',
    cipher: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

export function decryptBuffer(envelope, passphrase, expectedProfile) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new EnvstashError('Decryption passphrase cannot be empty', 'MISSING_KEY', 2);
  }
  if (!envelope || envelope.cipher !== 'aes-256-gcm' || envelope.kdf !== 'scrypt') {
    throw new EnvstashError('Unsupported or corrupted vault envelope format', 'CORRUPT_VAULT', 2);
  }

  let salt;
  let iv;
  let authTag;
  let ciphertext;
  try {
    salt = Buffer.from(envelope.salt, 'base64');
    iv = Buffer.from(envelope.iv, 'base64');
    authTag = Buffer.from(envelope.authTag, 'base64');
    ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  } catch {
    throw new EnvstashError('Invalid base64 fields in vault profile', 'CORRUPT_VAULT', 2);
  }

  if (salt.length !== SALT_BYTES || iv.length !== IV_BYTES || authTag.length !== AUTH_TAG_BYTES) {
    throw new EnvstashError(
      'Invalid salt, IV, or authentication tag length in vault profile',
      'CORRUPT_VAULT',
      2
    );
  }

  const derivedKey = crypto.scryptSync(passphrase, salt, KEY_BYTES, SCRYPT_PARAMS);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv, {
      authTagLength: AUTH_TAG_BYTES,
    });
    decipher.setAAD(buildAad(expectedProfile));
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new EnvstashError(
      'Decryption failed: wrong passphrase or tampered ciphertext (GCM authentication failed)',
      'AUTH_FAILED',
      2
    );
  } finally {
    derivedKey.fill(0);
  }
}
