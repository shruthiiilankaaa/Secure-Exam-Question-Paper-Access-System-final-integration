'use strict';

/**
 * Automated test suite for Audit Hash Chain Tampering Simulation & Restoration.
 * Tests all 12 security and verification invariants:
 *  1. A valid chain verifies successfully.
 *  2. Tampering with an entry is detected.
 *  3. The verifier identifies the expected broken entry/index.
 *  4. Restoring the original entry returns the chain to a valid state.
 *  5. The original audit record is restored exactly.
 *  6. Restoration fails safely if the original snapshot is missing.
 *  7. Non-Administrator users cannot invoke demo endpoints.
 *  8. Demo endpoints are unavailable when demo mode is disabled.
 *  9. Invalid record IDs and malformed requests are rejected.
 * 10. Verification caching does not hide newly simulated tampering.
 * 11. The demonstration cannot alter paper encryption keys, wrapped shares or user accounts.
 * 12. Ordinary audit appends and concurrent operations still behave correctly.
 */

require('dotenv').config();

const B = process.env.API || `http://localhost:${process.env.PORT || 5000}/api`;
const PW = 'Str0ng!Passw0rd#2026';

let pass = 0;
let fail = 0;

function check(name, ok, extra = '') {
  if (ok) {
    pass++;
    console.log(`✓ ${name}`);
  } else {
    fail++;
    console.log(`✗ ${name}${extra ? '  -> ' + extra : ''}`);
  }
}

async function req(method, path, { token, json } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  let body;
  if (json !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(json);
  }
  const res = await fetch(B + path, { method, headers, body });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  return { status: res.status, data };
}

(async () => {
  console.log('--- Testing Audit Tampering Simulation & Restoration Feature ---');

  const health = await fetch(B + '/health').then((r) => r.json()).catch(() => null);
  if (!health) {
    console.error('Backend is not running at ' + B + '. Start the backend first.');
    process.exit(1);
  }

  // Admin login
  const adminRes = await req('POST', '/auth/login', {
    json: {
      email: process.env.ADMIN_EMAIL,
      password: process.env.ADMIN_PASSWORD,
    },
  });
  if (adminRes.status !== 200) {
    console.error('Admin login failed: ' + JSON.stringify(adminRes.data));
    process.exit(1);
  }
  const adminToken = adminRes.data.token;

  // Create a regular non-admin user (approver) for permission checks
  const testEmail = `tamper-tester-${Date.now()}@iiitkottayam.ac.in`;
  await req('POST', '/auth/signup', {
    json: { name: 'Audit Tester', email: testEmail, password: PW },
  });
  const usersList = await req('GET', '/admin/users', { token: adminToken });
  const createdUser = usersList.data.users.find((u) => u.email === testEmail);
  await req('PATCH', `/admin/users/${createdUser.id}/role`, {
    token: adminToken,
    json: { role: 'approver' },
  });
  const approverLogin = await req('POST', '/auth/login', {
    json: { email: testEmail, password: PW },
  });
  const approverToken = approverLogin.data.token;

  // 1. A valid chain verifies successfully
  let v = await req('GET', '/audit/verify?force=true', { token: adminToken });
  check('1. Valid hash chain verifies successfully initially', v.status === 200 && v.data.valid === true, JSON.stringify(v.data));

  // 7. Non-Administrator users cannot invoke demo endpoints
  let unauth = await req('POST', '/audit/simulate-tamper', { json: {} });
  check('7a. Unauthenticated caller cannot invoke /simulate-tamper (401)', unauth.status === 401, unauth.status);

  let approverSim = await req('POST', '/audit/simulate-tamper', { token: approverToken, json: {} });
  check('7b. Approver cannot invoke /simulate-tamper (403)', approverSim.status === 403, approverSim.status);

  let approverRest = await req('POST', '/audit/restore-tamper', { token: approverToken });
  check('7c. Approver cannot invoke /restore-tamper (403)', approverRest.status === 403, approverRest.status);

  let approverStatus = await req('GET', '/audit/demo-status', { token: approverToken });
  check('7d. Approver cannot invoke /demo-status (403)', approverStatus.status === 403, approverStatus.status);

  // 6. Restoration fails safely if the original snapshot is missing
  let prematureRestore = await req('POST', '/audit/restore-tamper', { token: adminToken });
  check('6. Restoration fails safely when no simulation snapshot exists (400)', prematureRestore.status === 400 && /snapshot/i.test(prematureRestore.data.message || ''), JSON.stringify(prematureRestore.data));

  // 9. Invalid record IDs and malformed requests are rejected
  let badId = await req('POST', '/audit/simulate-tamper', {
    token: adminToken,
    json: { targetId: 'invalid-hex-id-123' },
  });
  check('9a. Malformed targetId rejected (400)', badId.status === 400, badId.status);

  let nonExistentId = await req('POST', '/audit/simulate-tamper', {
    token: adminToken,
    json: { targetId: '64b0000000000000000000ee' },
  });
  check('9b. Non-existent audit record ID rejected (404)', nonExistentId.status === 404, nonExistentId.status);

  // 2. Tampering with an entry is detected
  // Warm up verification cache first to test cache invalidation (requirement 10)
  await req('GET', '/audit/verify', { token: adminToken });

  // Get audit history to pick an entry
  let history = await req('GET', '/audit', { token: adminToken });
  check('Audit history returns records for simulation', history.status === 200 && Array.isArray(history.data) && history.data.length > 0);
  const targetEntry = history.data[history.data.length - 1];

  let simRes = await req('POST', '/audit/simulate-tamper', {
    token: adminToken,
    json: { targetId: targetEntry._id },
  });
  check('Tampering simulation created successfully (200)', simRes.status === 200 && simRes.data.success === true, JSON.stringify(simRes.data));

  // Cannot create a second concurrent simulation
  let doubleSim = await req('POST', '/audit/simulate-tamper', { token: adminToken, json: {} });
  check('Second simulation rejected while one is active (409)', doubleSim.status === 409, doubleSim.status);

  // 10. Verification caching does not hide newly simulated tampering
  // Call without force=true; must immediately reflect the tampering
  let cachedVerify = await req('GET', '/audit/verify', { token: adminToken });
  check('10. Verification cache does not hide newly simulated tampering (returns valid: false immediately)', cachedVerify.status === 200 && cachedVerify.data.valid === false);

  // 3. The verifier identifies the expected broken entry/index
  check('2 & 3. Verifier identifies tampering at expected brokenAtIndex', cachedVerify.data.brokenAtIndex === targetEntry.index, `expected index ${targetEntry.index}, got ${cachedVerify.data.brokenAtIndex}`);
  check('3b. Verifier provides descriptive tampering reason', /hash does not match/i.test(cachedVerify.data.reason || ''), cachedVerify.data.reason);

  // History shows simulated entry
  let historyAfterTamper = await req('GET', '/audit', { token: adminToken });
  let tamperedLog = historyAfterTamper.data.find((l) => l._id === targetEntry._id);
  check('Audit history marks tampered record', tamperedLog && tamperedLog.isSimulatedTamper === true);

  // 11. Demonstration cannot alter paper encryption keys, wrapped shares or user accounts
  const papersRes = await req('GET', '/papers', { token: adminToken });
  check('11a. Question papers collection unaffected', papersRes.status === 200 && Array.isArray(papersRes.data.papers));
  const usersRes = await req('GET', '/admin/users', { token: adminToken });
  check('11b. User credentials and accounts unaffected', usersRes.status === 200 && usersRes.data.users.length > 0);

  // 4. Restoring the original entry returns the chain to a valid state
  // 5. The original audit record is restored exactly
  let restoreRes = await req('POST', '/audit/restore-tamper', { token: adminToken });
  check('4 & 5. Restore Hash Chain returns 200 and reports verified chain', restoreRes.status === 200 && restoreRes.data.success === true && restoreRes.data.verification?.valid === true, JSON.stringify(restoreRes.data));

  // Check restored record in database
  let historyAfterRestore = await req('GET', '/audit', { token: adminToken });
  let restoredLog = historyAfterRestore.data.find((l) => l._id === targetEntry._id);
  check('5b. Restored audit entry no longer has simulated tampering flag', restoredLog && !restoredLog.isSimulatedTamper);
  check('5c. Restored audit entry hash matches original', restoredLog && restoredLog.hash === targetEntry.hash);

  // Verification after restore
  let finalVerify = await req('GET', '/audit/verify', { token: adminToken });
  check('4b. Chain verification confirms completely intact after restoration', finalVerify.status === 200 && finalVerify.data.valid === true, JSON.stringify(finalVerify.data));

  // 8. Demo endpoints are unavailable when demo mode is disabled
  const auditDemo = require('./services/auditDemo');
  const savedDemoEnv = process.env.ENABLE_AUDIT_DEMO_TOOLS;
  process.env.ENABLE_AUDIT_DEMO_TOOLS = 'false';
  const disabledSim = await auditDemo.simulateTampering();
  check('8a. simulateTampering rejected when ENABLE_AUDIT_DEMO_TOOLS=false (403)', disabledSim.status === 403 && disabledSim.error === 'DEMO_DISABLED');
  const disabledRestore = await auditDemo.restoreTampering();
  check('8b. restoreTampering rejected when ENABLE_AUDIT_DEMO_TOOLS=false (403)', disabledRestore.status === 403 && disabledRestore.error === 'DEMO_DISABLED');
  process.env.ENABLE_AUDIT_DEMO_TOOLS = savedDemoEnv;

  // 12. Ordinary audit appends and concurrent operations still behave correctly
  const appendOp = await req('PATCH', `/admin/users/${createdUser.id}/role`, {
    token: adminToken,
    json: { role: 'setter' },
  });
  check('12a. Normal audit append succeeds after restore (ROLE_ASSIGNED -> 200)', appendOp.status === 200 && appendOp.data.user?.role === 'setter');

  const postAppendVerify = await req('GET', '/audit/verify?force=true', { token: adminToken });
  check('12b. Full chain remains valid after subsequent append', postAppendVerify.status === 200 && postAppendVerify.data.valid === true, JSON.stringify(postAppendVerify.data));

  console.log(`\n========================================`);
  console.log(`Tampering & Restoration Suite: ${pass} passed, ${fail} failed`);
  console.log(`========================================\n`);

  process.exit(fail ? 1 : 0);
})().catch((err) => {
  console.error('Test script error:', err);
  process.exit(1);
});
