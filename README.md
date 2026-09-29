# Secure Exam Question Paper Access System

```
backend/    Express + MongoDB API (auth, papers, audit chain). Also serves ../frontend
frontend/   Static web UI (index.html, css/, js/) — talks to the backend's /api
crypto/     AES-256-GCM + Shamir secret sharing (used by backend/controllers/paperController.js)
```

## Run

```bash
cd backend
copy .env.example .env      # Windows (use cp on Mac/Linux), then edit MONGO_URI / JWT_SECRET/ADMIN_*
npm install
# REQUIRED: fill in JWT_SECRET, JWT_REFRESH_SECRET, AUDIT_HMAC_KEY, SHARE_WRAP_KEY in .env
# (the server refuses to start otherwise — generation one-liners are in .env.example)
npm run seed:admin           # creates just the first admin (see .env: ADMIN_EMAIL/ADMIN_PASSWORD)
# -- or, for a full test dataset --
npm run seed:users            # WIPES all users, recreates admin + a setter/approver/approver/invigilator/pending
npm run dev
```

Open http://localhost:5000 — the backend serves the frontend on the same port.

New accounts start as **pending**. Sign in as the admin (from `npm run seed:admin`),
go to the **Users** tab, and assign each signup a role (setter / approver / invigilator)
before they can log in. Signup only accepts `@iiitkottayam.ac.in` emails.

## Roles (enforced by the backend)

| Role        | Can do                                                            |
|-------------|-------------------------------------------------------------------|
| setter      | upload a paper, pick approvers + threshold k                      |
| approver    | approve papers they were designated for                           |
| invigilator | approve (if designated) and unlock/decrypt once k approvals + exam window are satisfied |
| admin       | assign roles to new signups (Users tab); cannot upload/approve/unlock |
| pending     | signed up, no role yet — cannot log in until an admin assigns one |
| everyone    | view papers relevant to them, audit log, audit verification       |

## Seeding test users

`npm run seed:users` clears the entire `users` collection and creates a ready-to-use
set: the admin from `.env`, plus one setter, two approvers, one invigilator and one
still-pending account — all `@iiitkottayam.ac.in`. The test accounts share a **random
password generated on every run and printed once at the end** (pin your own with
`SEED_PASSWORD=...`). Edit the `DEFAULT_USERS` list in `backend/scripts/seedUsers.js`
to change who gets created, or pass your own list:

```bash
npm run seed:users -- --file=./my-users.json
```
`my-users.json` is a JSON array of `{ "name", "email", "password", "role" }`. Every
entry is validated (domain + password strength) before anything is deleted, so a typo
in the file won't leave you with an empty database.

⚠️ This deletes every existing user, and refuses to run when `NODE_ENV=production` unless you add `--force-production`. Any paper's `approverIds` will then point at
accounts that no longer exist — fine for a clean test run, not for data you care about.

## Auth: access + refresh tokens

- **Access token**: 15 min, returned in the login/refresh response body, sent as
  `Authorization: Bearer <token>` on every API call. Carries no role — role is
  re-read from the DB on every request, so an admin's role change takes effect
  immediately, not at next login. It DOES carry `tokenVersion`, which is checked
  on every request: logout, role change and refresh-reuse detection revoke
  access tokens immediately (not after the 15 min expiry). The frontend keeps
  the token in memory only; a page reload restores the session through the
  httpOnly refresh cookie.
- **Refresh token**: 7 days, set as an **httpOnly** cookie (`refreshToken`,
  `Path=/api/auth`), never touched by frontend JS. `POST /api/auth/refresh`
  exchanges it for a new access token and **rotates** the cookie.
- **Reuse detection**: only the most recently issued refresh token is valid
  (tracked as `currentRefreshJti` on the user). Replaying an older one — the
  sign of a stolen token being used after the real client already rotated
  past it — revokes every token for that account (`tokenVersion` bump) instead
  of just failing quietly.
- **Logout** (`POST /api/auth/logout`) clears the cookie and bumps
  `tokenVersion`, so a stolen-but-unused refresh token stops working the
  moment the real user logs out — on any device.
- **Role change** (via the admin Users page) also bumps `tokenVersion`, so a
  demoted/promoted user's existing tokens die immediately.
- The frontend (`js/api.js`) restores the session silently on page load using
  the refresh cookie, and retries any request that gets a 401 with one
  refresh-and-retry before giving up.
- Set `JWT_SECRET` and `JWT_REFRESH_SECRET` in `.env` to two **different**
  long random strings — never reuse one for both.

## Key material (keep OUT of the database)

- `SHARE_WRAP_KEY` wraps every Shamir share stored in MongoDB (AES-256-GCM, bound to paper+approver).
  A DB dump/backup alone can no longer decrypt papers. **Back this key up separately — losing it
  makes existing papers undecryptable.** Upgrading an existing DB: `npm run migrate:shares`.
- `AUDIT_HMAC_KEY` keys the audit hash chain. Without it, a DB writer can't forge a valid chain.
  `GET /api/audit/verify` returns `headHash` — record it somewhere external periodically; that is
  what exposes tail truncation.
- Neither protects against a fully compromised *application server* (it holds both keys and does the unlock).

## Tests

```bash
node backend/test-units.js        # DB-free unit tests for the security patches (no MongoDB needed)
```

```bash
node crypto/test.js               # crypto unit tests (13)
node backend/test-auth-admin.js   # signup rules, pending accounts, admin role mgmt, rate limits
node backend/test-flow.js         # full paper flow: upload, approve, unlock, audit
```
Start the backend and run `npm run seed:admin` first.

## Testing tamper detection

There is intentionally no "tamper" API. To see the detector fire, edit an entry
directly in MongoDB (e.g. change an `action` in the `auditlogs` collection), then
open the Audit page and press **Verify Hash Chain Now**.
