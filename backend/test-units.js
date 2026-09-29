'use strict';
/**
 * DB-free unit tests for the security patches (share wrapping, keyed audit
 * chain, token-version enforcement, distinct approval counting).
 *   node test-units.js
 * Uses in-memory stand-ins for the Mongoose models, so no MongoDB is needed.
 */
const path = require('path');
const crypto = require('crypto');
const Module = require('module');

process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.JWT_REFRESH_SECRET = crypto.randomBytes(32).toString('hex');
process.env.AUDIT_HMAC_KEY = crypto.randomBytes(32).toString('hex');
process.env.SHARE_WRAP_KEY = crypto.randomBytes(32).toString('hex');

let pass = 0, fail = 0;
const check = (name, ok, extra = '') => { ok ? pass++ : fail++; console.log(`${ok ? '✓' : '✗'} ${name}${ok ? '' : '  -> ' + extra}`); };

// ---------- in-memory AuditLog stand-in (with the unique seq index) ----------
let rows = [], idc = 0;
const cmp = (spec) => (a, b) => {
  for (const [k, dir] of Object.entries(spec)) {
    const av = a[k] === undefined ? -Infinity : a[k], bv = b[k] === undefined ? -Infinity : b[k];
    if (av !== bv) return (av < bv ? -1 : 1) * dir;
  }
  return 0;
};
const q = (get) => { let spec = { _id: 1 }; const c = { sort(s) { spec = s; return c; }, lean() { return c; }, select() { return c; },
  then(res, rej) { return Promise.resolve(get(spec)).then(res, rej); } }; return c; };
const AuditLogStub = {
  findOne: () => q(async (spec) => { await null; return [...rows].sort(cmp(spec))[0] || null; }),
  find: () => q(async (spec) => { await null; return [...rows].sort(cmp(spec)).map((r) => ({ ...r })); }),
  countDocuments: async () => rows.length,
  create: async (doc) => {
    await null;
    if (typeof doc.seq === 'number' && rows.some((r) => r.seq === doc.seq)) { const e = new Error('E11000'); e.code = 11000; throw e; }
    const r = { ...doc, _id: ++idc }; rows.push(r); return r;
  },
};
const realLoad = Module._load;
const stubs = {};
Module._load = function (request, parent, ...rest) {
  for (const [suffix, mod] of Object.entries(stubs)) if (request.endsWith(suffix)) return mod;
  return realLoad.call(this, request, parent, ...rest);
};
stubs['models/AuditLog'] = AuditLogStub;

const audit = require('./services/auditLog');
const { wrapShare, unwrapShare, isWrapped } = require('../crypto/shareWrap');
const sha = (o) => crypto.createHash('sha256').update(o).digest('hex');

(async () => {
  // ================= share wrapping =================
  const share = crypto.randomBytes(33).toString('base64');
  const w = wrapShare(share, 'paper1', 'appr1');
  check('wrapped share is not the plaintext', isWrapped(w) && !w.includes(share));
  check('wrap/unwrap round trip', unwrapShare(w, 'paper1', 'appr1') === share);
  check('same share wraps differently each time (random IV)', wrapShare(share, 'paper1', 'appr1') !== w);
  let threw = false; try { unwrapShare(w, 'paper1', 'appr2'); } catch { threw = true; }
  check('share moved to another approver fails (AAD binding)', threw);
  threw = false; try { unwrapShare(w, 'paper2', 'appr1'); } catch { threw = true; }
  check('share moved to another paper fails (AAD binding)', threw);
  const tam = Buffer.from(w.slice(3), 'base64'); tam[tam.length - 1] ^= 1;
  threw = false; try { unwrapShare('v1:' + tam.toString('base64'), 'paper1', 'appr1'); } catch { threw = true; }
  check('tampered wrapped share fails', threw);
  const savedKey = process.env.SHARE_WRAP_KEY; process.env.SHARE_WRAP_KEY = crypto.randomBytes(32).toString('hex');
  threw = false; try { unwrapShare(w, 'paper1', 'appr1'); } catch { threw = true; }
  check('wrong wrap key fails (DB dump alone is useless)', threw);
  process.env.SHARE_WRAP_KEY = savedKey;
  check('legacy plaintext share still readable (migration path)', unwrapShare(share, 'p', 'a') === share);

  // ================= audit chain =================
  for (let i = 0; i < 5; i++) await audit.appendEntry({ action: 'A' + i, details: { i } });
  let v = await audit.verifyChain({ force: true });
  check('sequential appends verify', v.valid && v.entriesChecked === 5, JSON.stringify(v));
  check('entries are v2 with consecutive seq', rows.every((r, i) => r.v === 2 && r.seq === i + 1));

  rows = []; idc = 0;
  await Promise.all(Array.from({ length: 25 }, (_, i) => audit.appendEntry({ action: 'C' + i })));
  v = await audit.verifyChain({ force: true });
  check('25 CONCURRENT appends: chain does not fork', v.valid && v.entriesChecked === 25, JSON.stringify(v));
  check('no duplicate seq', new Set(rows.map((r) => r.seq)).size === 25);

  // attacker with DB write but WITHOUT the HMAC key edits an entry and "fixes" the hash with plain SHA-256
  const victim = rows[10];
  victim.details = { forged: true };
  victim.hash = sha(JSON.stringify({ x: 1 }));
  v = await audit.verifyChain({ force: true });
  check('edited entry + recomputed SHA-256 is detected (HMAC)', !v.valid, JSON.stringify(v));

  rows = []; idc = 0;
  for (let i = 0; i < 6; i++) await audit.appendEntry({ action: 'D' + i });
  const headBefore = (await audit.verifyChain({ force: true })).headHash;
  rows.splice(2, 1);
  v = await audit.verifyChain({ force: true });
  check('deleting a middle entry is detected', !v.valid, JSON.stringify(v));

  rows = []; idc = 0;
  for (let i = 0; i < 6; i++) await audit.appendEntry({ action: 'E' + i });
  const head = (await audit.verifyChain({ force: true })).headHash;
  rows.pop();
  v = await audit.verifyChain({ force: true });
  check('tail truncation is NOT detectable by the chain alone (known limit)…', v.valid === true);
  check('…but headHash changes, so anchoring the head externally catches it', v.headHash !== head);

  // legacy (pre-patch, plain SHA-256) rows followed by new v2 rows
  rows = []; idc = 0;
  const legacy = (prev, action) => { const e = { action, actor: null, paperId: null, details: {}, timestamp: new Date(), prevHash: prev };
    e.hash = sha(JSON.stringify({ action: e.action, actor: null, paperId: null, details: {}, timestamp: e.timestamp.toISOString(), prevHash: prev }));
    rows.push({ ...e, _id: ++idc }); return e.hash; };
  let h = legacy(audit.GENESIS_HASH, 'OLD1'); legacy(h, 'OLD2');
  await audit.appendEntry({ action: 'NEW1' }); await audit.appendEntry({ action: 'NEW2' });
  v = await audit.verifyChain({ force: true });
  check('legacy rows + new keyed rows verify together', v.valid && v.entriesChecked === 4, JSON.stringify(v));
  check('first keyed entry after legacy rows gets seq 3', rows[2].seq === 3);
  rows[0].action = 'HACKED';
  v = await audit.verifyChain({ force: true });
  check('tampered legacy row still detected', !v.valid);

  // ================= auth middleware: tokenVersion =================
  const jwt = require('jsonwebtoken');
  const usersDb = { u1: { role: 'setter', tokenVersion: 3 } };
  stubs['models/User'] = { findById: (id) => ({ select: () => ({ lean: async () => usersDb[id] || null }) }) };
  delete require.cache[require.resolve('./middleware/authMiddleware')];
  const authMw = require('./middleware/authMiddleware');
  const { signAccessToken } = require('./utils/tokens');
  const run = async (token) => { const res = { code: 200, status(c) { this.code = c; return this; }, json() { return this; } }; let nexted = false;
    await authMw({ headers: { authorization: 'Bearer ' + token } }, res, () => { nexted = true; }); return nexted ? 200 : res.code; };

  check('token with current tokenVersion accepted', (await run(signAccessToken({ _id: 'u1', tokenVersion: 3 }))) === 200);
  usersDb.u1.tokenVersion = 4; // logout / role change / reuse-detection
  check('same token rejected after tokenVersion bump (logout revokes access tokens)', (await run(signAccessToken({ _id: 'u1', tokenVersion: 3 }))) === 401);
  usersDb.u1.tokenVersion = 3;
  const legacyTok = jwt.sign({ userId: 'u1', type: 'access' }, process.env.JWT_SECRET, { expiresIn: '5m' });
  check('pre-patch token without tokenVersion rejected (client silently refreshes)', (await run(legacyTok)) === 401);
  const noType = jwt.sign({ userId: 'u1', tokenVersion: 3 }, process.env.JWT_SECRET, { expiresIn: '5m' });
  check('token without type claim rejected', (await run(noType)) === 401);
  const refreshTyped = jwt.sign({ userId: 'u1', tokenVersion: 3, type: 'refresh' }, process.env.JWT_SECRET, { expiresIn: '5m' });
  check('refresh-typed token rejected as access token', (await run(refreshTyped)) === 401);

  // ================= Paper: distinct approvals =================
  const Paper = require('./models/Paper');
  const oid = () => new (require('mongoose').Types.ObjectId)();
  const a = oid(), b = oid();
  const p = new Paper({ title: 't', originalFilename: 'f', uploadedBy: oid(), ciphertext: Buffer.from('x'), n: 3, k: 2,
    approverIds: [a, b], examStartTime: new Date(), examEndTime: new Date(),
    approvals: [{ approverId: a }, { approverId: a }, { approverId: a }] });
  check('same approver recorded 3x counts as 1', p.approvalCount() === 1 && !p.meetsThreshold());
  p.approvals.push({ approverId: b });
  check('two distinct approvers meet k=2', p.approvalCount() === 2 && p.meetsThreshold());

  // ================= access helpers =================
  const { canViewPaper } = require('./utils/access');
  const paper = { uploadedBy: a, approverIds: [b] };
  check('setter sees own paper only', canViewPaper(paper, { userId: String(a), role: 'setter' }) && !canViewPaper(paper, { userId: String(oid()), role: 'setter' }));
  check('approver sees designated paper only', canViewPaper(paper, { userId: String(b), role: 'approver' }) && !canViewPaper(paper, { userId: String(oid()), role: 'approver' }));
  check('invigilator/admin see all', canViewPaper(paper, { userId: 'x', role: 'invigilator' }) && canViewPaper(paper, { userId: 'x', role: 'admin' }));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
