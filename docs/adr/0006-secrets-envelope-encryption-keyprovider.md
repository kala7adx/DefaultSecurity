# 0006. Secrets: envelope encryption behind a KeyProvider

- Status: Accepted (owner approval 2026-11-23)
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
`CLAUDE.md` rule 3: secrets are encrypted at rest with envelope encryption behind a
`KeyProvider` interface (local, AWS KMS, Azure Key Vault, GCP KMS). Rule 4: redact
secret-bearing fields in collected config and keep a hash, not the value. Brief §8: separate the
collector identity from the API identity, and workers hold credentials only in memory for the
duration of a job. Most integrations hold no long-lived secret at all (AWS role ARN +
ExternalId), but some do: certificate private keys for self-hosted Entra apps, GCP keys as a last
resort, and HMAC keys.

## Decision
- **`KeyProvider` protocol:** `generate_data_key(ctx) -> DataKey(plaintext, wrapped, key_id)` and
  `unwrap(wrapped, key_id, ctx) -> plaintext`.
  - Implementations: `local` in Phase 0; `aws-kms`, `azure-keyvault` and `gcp-kms` in Phase 4.
- **Envelope format (`SecretBox`):**
  - A fresh 256-bit DEK per secret. AES-256-GCM (`cryptography`), with a fresh random 96-bit
    nonce for each encryption.
  - AAD is the canonical encoding of `{format_version, tenant_id, secret_id, purpose}`, so moving
    a ciphertext to another tenant, secret or purpose fails authentication.
  - The `secrets` table stores `key_provider`, `key_id`, `wrapped_dek`, `nonce`, `ciphertext` and
    `format_version`, and never plaintext.
- **Local provider:**
  - The KEK is 32 random bytes from a file (`SKYLINE_LOCAL_KEK_FILE`) created by `secrets-init`.
  - DEKs are wrapped with AES-256-GCM (random nonce, AAD = context).
  - Several KEK versions can exist at once (`key_id`): the active one wraps, older ones unwrap.
  - Rotation re-wraps DEKs only, as a documented admin command.
- **Cloud KMS providers:**
  - The encryption context carries `tenant_id`, `purpose` and `secret_id`, and key policies apply
    conditions to that context.
  - **The API identity can only `GenerateDataKey`/`Encrypt`; the worker identity can only
    `Decrypt`**, so an API compromise can't decrypt stored credentials.
  - SaaS mode (Phase 9) adds per-tenant KMS keys.
- **Handling plaintext:**
  - Decrypted credentials live only in the worker, inside a `Secret[T]` wrapper whose `repr` is
    masked. They are dropped when the job ends.
  - DEK buffers are `bytearray`s, zeroed on a best-effort basis (Python can't guarantee it).
- **DB grants:** `skyline_api` has INSERT but no SELECT on `secrets.wrapped_dek`/`ciphertext`
  (column privileges).
- **Raw-config redaction:** secret-bearing fields are replaced with
  `{"redacted": true, "hmac": HMAC-SHA256(k_tenant, value)}`. `k_tenant` is a per-tenant HMAC key,
  itself stored as a sealed secret. A bare SHA-256 would let low-entropy values (passwords in user
  data) be brute-forced offline.

## Consequences
- A database dump alone reveals no secrets. With KMS, it also needs the worker's KMS identity.
- The local provider puts the KEK on the same host as the database. That's acceptable for dev
  and small single-VM installs, and documented as a residual risk with KMS as the mitigation.
- More moving parts than a single app-level key, but each piece is small and tested: tamper,
  wrong-AAD, wrong-tenant and unknown-key_id cases.

## Alternatives considered
- `pgcrypto` in the database: puts keys and plaintext through SQL and logs.
- A single static app key: no rotation, no API/worker split.
- Fernet: fine, but its AES-128-CBC+HMAC is less flexible than AES-GCM with AAD binding.

## References
- `cryptography` AESGCM: https://cryptography.io/en/latest/hazmat/primitives/aead/
- AWS KMS encryption context: https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html
- NIST SP 800-38D (GCM nonce requirements).
