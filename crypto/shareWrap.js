'use strict';

/**
 * Wraps each Shamir share with AES-256-GCM under a key (SHARE_WRAP_KEY) that
 * lives OUTSIDE the database (env / secrets manager / KMS-fed env var).
 *
 * Effect: a DB dump, backup or read-only DB access no longer yields usable
 * shares. The AAD binds a wrapped share to its (paperId, approverId), so
 * shares can't be swapped between rows.
 *
 * NOT protected against: a compromised application server (it holds the wrap
 * key and performs the unlock). For that, move unwrap into a KMS/HSM.
 *
 * Format: "v1:" + base64( iv(12) | tag(16) | ciphertext )
 */

const crypto = require('crypto');

const PREFIX = 'v1:';

function loadWrapKey() {
  const raw = process.env.SHARE_WRAP_KEY || '';
  let key;
  if (/^[0-9a-fA-F]{64}$/.test(raw)) key = Buffer.from(raw, 'hex');
  else key = Buffer.from(raw, 'base64');
  if (key.length !== 32) throw new Error('must decode to exactly 32 bytes');
  return key;
}

const aad = (paperId, approverId) => Buffer.from(`share|${paperId}|${approverId}`);

function wrapShare(share, paperId, approverId) {
  const key = loadWrapKey();
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad(paperId, approverId));
  const ct = Buffer.concat([c.update(share, 'utf8'), c.final()]);
  return PREFIX + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}

function isWrapped(stored) {
  return typeof stored === 'string' && stored.startsWith(PREFIX);
}

function unwrapShare(stored, paperId, approverId) {
  if (!isWrapped(stored)) {
    // Legacy plaintext row (pre-patch). Still readable so old papers keep working;
    // run scripts/wrapExistingShares.js to migrate.
    return stored;
  }
  const key = loadWrapKey();
  const buf = Buffer.from(stored.slice(PREFIX.length), 'base64');
  if (buf.length < 12 + 16 + 1) throw new Error('wrapped share malformed');
  const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  d.setAAD(aad(paperId, approverId));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}

module.exports = { wrapShare, unwrapShare, isWrapped, loadWrapKey };
