# Security patch notes

| # | Finding | Fix | Where |
|---|---------|-----|-------|
| 1 | Shares stored in plaintext beside ciphertext | Shares AES-256-GCM-wrapped under `SHARE_WRAP_KEY` (outside DB), AAD-bound to paper+approver; legacy rows still readable; `npm run migrate:shares` | `crypto/shareWrap.js`, `paperController.js`, `scripts/wrapExistingShares.js` |
| 2 | Unkeyed, forkable audit chain | HMAC-SHA256 (`AUDIT_HMAC_KEY`), `seq` with unique index, serialized appends + retry, cached verify, `headHash` for external anchoring | `services/auditLog.js`, `models/AuditLog.js` |
| 3 | Upload validation | Approver ids: format/unique/exist/role; strict `k`; date sanity; title/filename sanitizing; compensating cleanup on failure | `paperController.js` |
| 4 | No upload size limit | multer limits (10 MB default, 15 max), 413 handling | `paperRoutes.js`, `server.js` |
| 5 | Racy approval counting | Atomic `findOneAndUpdate` with `$ne` guard; distinct-approver counting | `paperController.js`, `models/Paper.js` |
| 6 | Access tokens not revocable | `tokenVersion` in access token, enforced per request | `utils/tokens.js`, `authMiddleware.js` |
| 8 | Over-broad reads | Status scoped (404 if not visible); audit scoped by role, emails hidden from non-privileged; verify rate-limited | `access.js`, `auditController.js`, `rateLimiters.js` |
| 9 | Frontend hardening | CSP (`script-src 'self'`) + security headers, no inline handlers, textContent toasts, token in memory only | `server.js`, `frontend/js/*`, `index.html` |
| — | Also fixed | Fail-fast env validation; CORS no longer reflects any origin; central error handler (no stack traces); `Content-Disposition` via `res.attachment`, success recorded only after response is built; bad ObjectId → 400/404 | `config/env.js`, `server.js` |

Seed scripts: `seed:users` now generates a random password per run (or `SEED_PASSWORD`), refuses to run under `NODE_ENV=production` without `--force-production`, and warns about the `.env.example` admin placeholder; `seed:admin` refuses that placeholder in production and revokes tokens when promoting an existing user.

Deliberately NOT changed: email verification (#7), and the other low-priority items (enumeration timing, bcrypt cost).

## Deploying over an existing database
1. Generate the four secrets (see `.env.example`), add to `.env`.
2. `npm run migrate:shares` (wraps existing plaintext shares; idempotent).
3. Existing audit rows stay valid (legacy SHA-256 rows verify as before; new rows are HMAC'd). Legacy rows remain forgeable by a DB writer — they predate the key.
4. Users are signed out once (old access tokens carry no `tokenVersion`); silent refresh handles it.
