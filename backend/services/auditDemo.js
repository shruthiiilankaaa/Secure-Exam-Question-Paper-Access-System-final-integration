'use strict';

const AuditLog = require('../models/AuditLog');
const { verifyChain, invalidateVerifyCache, SORT_DESC } = require('./auditLog');

const OBJECT_ID_REGEX = /^[a-f0-9]{24}$/i;

let currentDemoSnapshot = null;

function isAuditDemoEnabled() {
  return process.env.ENABLE_AUDIT_DEMO_TOOLS === 'true' || process.env.ENABLE_AUDIT_DEMO_TOOLS === '1';
}

function getDemoStatus() {
  return {
    enabled: isAuditDemoEnabled(),
    activeSimulation: currentDemoSnapshot ? {
      entryId: currentDemoSnapshot.entryId,
      seq: currentDemoSnapshot.seq,
      action: currentDemoSnapshot.action,
      tamperedAt: currentDemoSnapshot.tamperedAt,
      modifiedField: 'details',
    } : null,
  };
}

async function simulateTampering({ targetId } = {}) {
  if (!isAuditDemoEnabled()) {
    return {
      status: 403,
      error: 'DEMO_DISABLED',
      message: 'Audit demonstration tools are disabled in this environment',
    };
  }

  if (currentDemoSnapshot) {
    return {
      status: 409,
      error: 'SIMULATION_ALREADY_ACTIVE',
      message: `A tampering simulation is already active on entry #${currentDemoSnapshot.seq ?? currentDemoSnapshot.entryId}. Restore the hash chain first.`,
      activeSimulation: {
        entryId: currentDemoSnapshot.entryId,
        seq: currentDemoSnapshot.seq,
        action: currentDemoSnapshot.action,
      },
    };
  }

  let entry;
  if (targetId) {
    if (typeof targetId !== 'string' || !OBJECT_ID_REGEX.test(targetId)) {
      return { status: 400, error: 'INVALID_ID', message: 'Invalid audit entry ID format' };
    }
    entry = await AuditLog.findById(targetId);
    if (!entry) {
      return { status: 404, error: 'NOT_FOUND', message: 'Target audit entry not found' };
    }
  } else {
    entry = await AuditLog.findOne().sort(SORT_DESC);
    if (!entry) {
      return { status: 400, error: 'NO_ENTRIES', message: 'No audit records found to tamper' };
    }
  }

  // Preserve the exact original document before modifying anything
  const snapshot = {
    _id: entry._id,
    action: entry.action,
    actor: entry.actor ? entry.actor.toString() : null,
    paperId: entry.paperId ? entry.paperId.toString() : null,
    details: JSON.parse(JSON.stringify(entry.details || {})),
    timestamp: new Date(entry.timestamp),
    prevHash: entry.prevHash,
    hash: entry.hash,
    v: entry.v,
    seq: entry.seq,
  };

  currentDemoSnapshot = {
    entryId: entry._id.toString(),
    seq: entry.seq,
    action: entry.action,
    original: snapshot,
    tamperedAt: new Date(),
  };

  // Harmless field modification: modify details WITHOUT updating HMAC / hash
  const tamperedDetails = {
    ...snapshot.details,
    _simulatedTamper: {
      isTampered: true,
      tamperedAt: new Date().toISOString(),
      note: 'Demonstration simulation: audit entry details modified without recalculating cryptographic hash',
    },
  };

  await AuditLog.updateOne(
    { _id: entry._id },
    { $set: { details: tamperedDetails } }
  );

  // Invalidate verification cache so subsequent verifications reflect tampering immediately
  invalidateVerifyCache();

  return {
    status: 200,
    success: true,
    message: 'Tampering simulation created: audit entry details modified without recalculating hash',
    entryId: entry._id.toString(),
    seq: entry.seq,
    action: entry.action,
    modifiedField: 'details',
  };
}

async function restoreTampering() {
  if (!isAuditDemoEnabled()) {
    return {
      status: 403,
      error: 'DEMO_DISABLED',
      message: 'Audit demonstration tools are disabled in this environment',
    };
  }

  if (!currentDemoSnapshot) {
    return {
      status: 400,
      error: 'NO_SNAPSHOT',
      message: 'No simulation snapshot found. Server may have been restarted; safe restoration cannot guess or reconstruct lost audit records.',
    };
  }

  const orig = currentDemoSnapshot.original;
  const existing = await AuditLog.findById(orig._id);
  if (!existing) {
    return {
      status: 404,
      error: 'NOT_FOUND',
      message: 'Target audit entry no longer exists in the database',
    };
  }

  // Restore the exact original fields from the snapshot
  await AuditLog.updateOne(
    { _id: orig._id },
    {
      $set: {
        action: orig.action,
        actor: orig.actor,
        paperId: orig.paperId,
        details: orig.details,
        timestamp: orig.timestamp,
        prevHash: orig.prevHash,
        hash: orig.hash,
        v: orig.v,
        seq: orig.seq,
      },
    }
  );

  // Verify that the restored document in the DB matches the snapshot exactly
  const restored = await AuditLog.findById(orig._id).lean();
  const matches = restored &&
    restored.action === orig.action &&
    String(restored.actor || '') === String(orig.actor || '') &&
    String(restored.paperId || '') === String(orig.paperId || '') &&
    JSON.stringify(restored.details || {}) === JSON.stringify(orig.details || {}) &&
    new Date(restored.timestamp).getTime() === orig.timestamp.getTime() &&
    restored.prevHash === orig.prevHash &&
    restored.hash === orig.hash &&
    restored.v === orig.v &&
    restored.seq === orig.seq;

  if (!matches) {
    return {
      status: 500,
      error: 'RESTORE_MISMATCH',
      message: 'Restored document did not match original snapshot',
    };
  }

  // Invalidate verification cache
  invalidateVerifyCache();

  // Run verification to confirm the hash chain is cryptographically valid
  const verification = await verifyChain({ force: true });
  if (!verification.valid) {
    return {
      status: 409,
      error: 'CHAIN_STILL_INVALID',
      message: `Original record restored, but chain verification failed: ${verification.reason || 'unknown'}`,
      verification,
    };
  }

  // Successfully restored and verified; clear in-memory snapshot
  currentDemoSnapshot = null;

  return {
    status: 200,
    success: true,
    message: 'Audit record restored to original state and hash chain verified intact',
    restoredEntryId: orig._id.toString(),
    seq: orig.seq,
    action: orig.action,
    verification,
  };
}

function resetDemoState() {
  currentDemoSnapshot = null;
  invalidateVerifyCache();
}

module.exports = {
  isAuditDemoEnabled,
  getDemoStatus,
  simulateTampering,
  restoreTampering,
  resetDemoState,
};
