# envstash

Zero-dependency Node 24 ESM encrypted local `.env` and `.dev.vars` profile vault for ephemeral git worktrees.

## Security Model

- **Key Derivation**: `node:crypto` `scryptSync` (`N=16384, r=8, p=1`) with a fresh 32-byte random salt on every save.
- **Authenticated Encryption**: `AES-256-GCM` with a fresh 12-byte random IV, 16-byte authentication tag, and profile-bound AAD (`envstash:v1:<profile>`).
- **Zero Plaintext Metadata**: Vault JSON files record only key count, source filename, and timestamps; secret values are never stored or printed in metadata.
- **Git-Ignore Preflight**: `envstash apply` verifies the target file (`.env` or `.dev.vars`) is ignored by git (`git check-ignore` or `.gitignore`) *before* decrypting or writing any plaintext to disk, exiting with code `2` unless `--force-unignored` is explicitly passed.
- **Secure Worktree Cleanup**: `envstash strip` overwrites injected secret files with random bytes and zeros (`fsync`) before unlinking.

## Usage

```bash
# Save an encrypted profile (using ENVSTASH_KEY or --key-file)
envstash save api-dev --from ./.env --key-file ~/.envstash.key

# List saved profiles, key counts, and timestamps
envstash ls [--json]

# Apply profile into a git-ignored worktree file
envstash apply api-dev --repo-dir ../worktree-feat --to .env --key-file ~/.envstash.key

# Securely wipe .env / .dev.vars from a finished worktree
envstash strip --repo-dir ../worktree-feat
```

On Windows PowerShell:

```powershell
npm.cmd test
$env:ENVSTASH_KEY = "strong-local-passphrase"
node .\bin\envstash.js ls
```

Default vault location on Windows: `D:\Codex\Projects\.cache\envstash` (override with `--vault-dir` or `ENVSTASH_VAULT`).

## Exit Codes

- `0`: Success
- `1`: Invalid CLI arguments
- `2`: Security refusal (unignored target), wrong passphrase (GCM auth failure), or vault error

## License

MIT
