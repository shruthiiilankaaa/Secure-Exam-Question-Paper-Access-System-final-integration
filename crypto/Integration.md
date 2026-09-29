# Crypto Core — Integration Guide (for Person C)

This document explains how to integrate the crypto core (`aes.js`, `gf256.js`,
`shamir.js`, `paperCrypto.js`) into the question-paper upload and unlock
workflow. You should not need to read or modify the crypto files themselves —
everything you need is exposed through `paperCrypto.js`.

## Status

- AES-256-GCM encryption/decryption: implemented, tested
- Shamir's Secret Sharing (N shares, K threshold): implemented, tested
- Full test suite: 13/13 passing (`node test.js`)
- Security check performed: `npm audit` clean, ESLint security scan clean,
  manual review against a standard crypto checklist (see `SECURITY.md` if
  you want the details)

## What you get

```js
const { encryptPaper, decryptPaper } = require('./paperCrypto');
```

### `encryptPaper(fileBuffer, n, k)`

Encrypts a file and splits its key.

- `fileBuffer` — `Buffer`, the raw question paper file (PDF, docx, whatever —
  it's treated as opaque bytes)
- `n` — total number of shares to generate (e.g. number of approvers: HOD,
  exam controller, invigilator = 3)
- `k` — minimum number of shares needed to reconstruct the key (e.g. 2)

Returns:
```js
{
  ciphertext: Buffer,   // encrypted file — safe to store, useless without the key
  shares: string[]      // array of `n` base64 strings, one share each
}
```

### `decryptPaper(ciphertext, shares)`

Reconstructs the key from shares and decrypts.

- `ciphertext` — the `Buffer` returned by `encryptPaper`
- `shares` — an array of `>= k` share strings (from the `shares` array above)

Returns: the original file `Buffer`.

Throws a generic `Error` if the shares are insufficient/wrong or the
ciphertext is corrupted/tampered. The error message is deliberately vague
(`"decryption failed: invalid key, corrupted data, or tampered ciphertext"`)
— it does not tell you *why* it failed, by design, so failed attempts can't
be used to probe the system. Treat any thrown error as a denied/failed
access attempt in your workflow and audit log.

## What you need to build around it

### 1. On question paper upload

```js
const { ciphertext, shares } = encryptPaper(fileBuffer, N, K);
```

- Store `ciphertext` in your DB/filesystem — this is safe on its own, it's
  useless without a key.
- Distribute `shares[0]`, `shares[1]`, ... one per approver, tied to that
  approver's user ID (this connects to Person A's role/user system).
- **Never store more than one share in the same place.** If all shares end
  up in the same DB row or file, you've defeated the entire point of
  splitting the key — a single leak of that row leaks the paper.
- Decide `N` and `K` per your threat model. Example: 3 approvers (HOD,
  exam controller, invigilator), require 2 of them (`N=3, K=2`) so no
  single person can unlock it alone, but you're not blocked if one person
  is unavailable.

### 2. On an unlock request

This should only be attempted after:
- Person A's auth/role checks pass (only Approvers/Invigilators as defined)
- Your approval-count check passes (>= K approvers have actually approved
  *this specific request*)
- Your time-lock check passes (current time is within the authorized exam
  window)

Only once all of the above are true:

```js
try {
  const collectedShares = getApprovedSharesForThisRequest(requestId); // your code
  const originalFile = decryptPaper(ciphertext, collectedShares);
  // return/serve originalFile to the invigilator
} catch (err) {
  // Log this as a denied/failed attempt in Person D's audit log.
  // Do not show err.message directly to the end user if you want to be
  // extra careful — a generic "access denied" is safer UX.
}
```

### 3. What's NOT handled by the crypto core (by design)

These are explicitly your responsibility, not something to expect from
`paperCrypto.js`:

- **Who submitted which share** — the module only cares that you pass it
  `>= k` valid shares. It has no concept of identity; that's Person A/C's
  job to check before calling `decryptPaper`.
- **Approval workflow / counting approvals** — the module doesn't know
  what "2 of 3 approved" means. You track that state and only call
  `decryptPaper` once the threshold of *approved* shares is met.
- **Time-lock enforcement** — the module will happily decrypt at 3am if
  you call it then. The time check must happen in your code, before you
  ever call `decryptPaper`.
- **Storing shares securely** — the module returns shares as plain base64
  strings. How/where you store them (DB column, encrypted-at-rest, etc.)
  is your decision. See the note below on a known limitation.

## Known limitation worth reflecting in your threat-model write-up

The server process that calls `decryptPaper()` sees the fully reconstructed
AES key in memory for a brief moment, even though no *individual approver*
ever saw the full key. This means:

- The "no single point of trust" guarantee applies to the *approvers*, not
  to the server itself. If the application server running this code is
  compromised, threshold trust doesn't help — the attacker can just wait
  for a legitimate decrypt to happen and capture the key from memory, or
  call `decryptPaper` directly if they've breached the server.
- We mitigate this modestly: `paperCrypto.js` zeroes out the raw key buffer
  immediately after use (`aes.wipe()`), but this is best-effort in Node.js
  and does not guarantee no copies exist elsewhere in memory.
- Worth stating explicitly in your threat model: this system defends
  against *a single dishonest or compromised approver*, not against a
  *compromised application server*. Those are different threats.

## Quick integration checklist

- [ ] Call `encryptPaper` on upload, store `ciphertext`, distribute `shares`
      to approvers by user ID
- [ ] Never co-locate more than one share
- [ ] Gate every call to `decryptPaper` behind: auth check (Person A) +
      approval-count check (yours) + time-lock check (yours)
- [ ] Wrap `decryptPaper` in try/catch; log both success and failure to
      Person D's audit log
- [ ] Don't expose raw error messages from `decryptPaper` to end users
- [ ] Confirm your `N`/`K` values match your actual approver roles before
      going further (e.g. 3 approvers, need 2)