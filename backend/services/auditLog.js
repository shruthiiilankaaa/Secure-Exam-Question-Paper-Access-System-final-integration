'use strict';

const crypto = require('crypto');
const AuditLog = require('../models/AuditLog');

const GENESIS_HASH = '0'.repeat(64);
const SORT = { seq: 1, _id: 1 };       // legacy rows (no seq) sort first, by _id
const SORT_DESC = { seq: -1, _id: -1 };

function hmacKey() {
  const k = process.env.AUDIT_HMAC_KEY;
  if (!k) throw new Error('AUDIT_HMAC_KEY is not set');
  return k;
}

function canonicalize(entry) {
  const base = {
    action: entry.action,
    actor: entry.actor ? entry.actor.toString() : null,
    paperId: entry.paperId ? entry.paperId.toString() : null,
    details: entry.details || {},
    timestamp: entry.timestamp.toISOString(),
    prevHash: entry.prevHash,
  };
  // v2 also commits to seq (so entries can't be reordered/renumbered)
  if (entry.v === 2) { base.v = 2; base.seq = entry.seq; }
  return JSON.stringify(base);
}

function computeHash(entry) {
  const data = canonicalize(entry);
  if (entry.v === 2) return crypto.createHmac('sha256', hmacKey()).update(data).digest('hex');
  return crypto.createHash('sha256').update(data).digest('hex'); // legacy
}

let verifyCache = null; // { at, result }
const VERIFY_TTL_MS = 15 * 1000;

// In-process queue: appends from this process run one at a time, so the only
// contention left is between separate server processes (handled by the unique
// seq index + retry below).
let queue = Promise.resolve();

async function appendOnce({ action, actor, paperId, details }) {
  const last = await AuditLog.findOne().sort(SORT_DESC).lean();
  const prevHash = last ? last.hash : GENESIS_HASH;
  let seq;
  if (!last) seq = 1;
  else if (typeof last.seq === 'number') seq = last.seq + 1;
  else seq = (await AuditLog.countDocuments()) + 1; // first v2 entry after legacy rows

  const draft = { action, actor, paperId, details, timestamp: new Date(), prevHash, v: 2, seq };
  return AuditLog.create({ ...draft, hash: computeHash(draft) });
}

/**
 * Append a chained entry. A unique index on seq guarantees the chain cannot
 * fork; if another process claimed the slot first we re-read the tail and retry.
 * NEVER put raw shares, keys or raw crypto errors in `details`.
 */
function appendEntry({ action, actor = null, paperId = null, details = {} }) {
  const job = queue.then(async () => {
    for (let attempt = 0; attempt < 12; attempt++) {
      try {
        const created = await appendOnce({ action, actor, paperId, details });
        verifyCache = null;
        return created;
      } catch (err) {
        if (!(err && err.code === 11000)) throw err;
        await new Promise((r) => setTimeout(r, Math.random() * 20 * (attempt + 1))); // jittered backoff
      }
    }
    throw new Error('audit append failed: too much contention');
  });
  queue = job.catch(() => {}); // a failed append must not wedge the queue
  return job;
}

/**
 * Walk the whole chain. Legacy rows are checked with SHA-256 (forgeable by a
 * DB writer — they predate the HMAC); v2 rows are checked with the HMAC and
 * must have consecutive seq numbers.
 */
async function verifyChain({ force = false } = {}) {
  if (!force && verifyCache && Date.now() - verifyCache.at < VERIFY_TTL_MS) return verifyCache.result;

  const entries = await AuditLog.find().sort(SORT).lean();
  let expectedPrevHash = GENESIS_HASH;
  let prevSeq = null;
  let result = null;

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.prevHash !== expectedPrevHash) {
      result = { valid: false, brokenAtIndex: i, reason: 'prevHash mismatch (record deleted/reordered?)', entriesChecked: entries.length };
      break;
    }
    if (e.v === 2) {
      if (prevSeq !== null && e.seq !== prevSeq + 1) {
        result = { valid: false, brokenAtIndex: i, reason: 'sequence gap (record deleted/inserted?)', entriesChecked: entries.length };
        break;
      }
      prevSeq = e.seq;
    } else if (prevSeq !== null) {
      result = { valid: false, brokenAtIndex: i, reason: 'legacy entry after keyed entries', entriesChecked: entries.length };
      break;
    }
    if (computeHash(e) !== e.hash) {
      result = { valid: false, brokenAtIndex: i, reason: 'stored hash does not match recomputed hash (record modified)', entriesChecked: entries.length };
      break;
    }
    expectedPrevHash = e.hash;
  }

  if (!result) {
    result = {
      valid: true, brokenAtIndex: null, reason: null, entriesChecked: entries.length,
      // Publish/anchor this externally (e-mail, git, WORM storage) to detect tail truncation.
      headHash: expectedPrevHash,
    };
  }
  verifyCache = { at: Date.now(), result };
  return result;
}

function invalidateVerifyCache() {
  verifyCache = null;
}

module.exports = { appendEntry, verifyChain, invalidateVerifyCache, computeHash, GENESIS_HASH, SORT, SORT_DESC };
