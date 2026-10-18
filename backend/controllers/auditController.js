'use strict';

const AuditLog = require('../models/AuditLog');
const Paper = require('../models/Paper');
const { verifyChain, SORT } = require('../services/auditLog');
const { paperFilterFor } = require('../utils/access');

const OBJECT_ID = /^[a-f0-9]{24}$/i;
const PRIVILEGED = new Set(['admin', 'invigilator']);

const {
  getDemoStatus,
  simulateTampering,
  restoreTampering,
} = require('../services/auditDemo');

// History. admin/invigilator see everything (incl. actor e-mails); everyone
// else only sees entries for papers they may view plus their own actions,
// and never other people's e-mail addresses.
const getAuditHistory = async (req, res) => {
  try {
    const { userId, role } = req.user;
    const privileged = PRIVILEGED.has(role);

    let paperId = req.query.paperId;
    if (paperId !== undefined) {
      if (typeof paperId !== 'string' || !OBJECT_ID.test(paperId)) {
        return res.status(400).json({ message: 'invalid paperId' });
      }
    }

    // Position of every entry in the full chain, so `index` lines up with
    // /audit/verify's brokenAtIndex even when the list is filtered.
    const all = await AuditLog.find().sort(SORT).select('_id').lean();
    const position = new Map(all.map((e, i) => [String(e._id), i]));

    let filter = paperId ? { paperId } : {};
    if (!privileged) {
      const visible = await Paper.find(paperFilterFor(req.user)).distinct('_id');
      if (paperId && !visible.some((id) => String(id) === paperId)) return res.json([]);
      filter = paperId ? { paperId } : { $or: [{ actor: userId }, { paperId: { $in: visible } }] };
    }

    const entries = await AuditLog.find(filter)
      .sort(SORT)
      .populate('actor', privileged ? 'name email role' : 'name role')
      .populate('paperId', 'title')
      .lean();

    return res.json(entries.map((e) => ({
      ...e,
      index: position.get(String(e._id)),
      isSimulatedTamper: !!(e.details && e.details._simulatedTamper),
    })));
  } catch (err) {
    console.error('audit history error:', err);
    return res.status(500).json({ message: 'could not load audit log' });
  }
};

// Integrity check — cached + rate-limited (see routes / service).
const verifyAuditChain = async (req, res) => {
  try {
    const force = req.query.force === 'true' || req.query.force === '1';
    return res.json(await verifyChain({ force }));
  } catch (err) {
    console.error('audit verify error:', err);
    return res.status(500).json({ message: 'could not verify audit log' });
  }
};

// Demo status (enabled flag + active simulation info)
const getAuditDemoStatus = async (req, res) => {
  try {
    return res.json(getDemoStatus());
  } catch (err) {
    console.error('audit demo status error:', err);
    return res.status(500).json({ message: 'could not get audit demo status' });
  }
};

// Create a deliberate tampering simulation (Admin + demo flag only)
const simulateAuditTamper = async (req, res) => {
  try {
    const { targetId } = req.body || {};
    if (targetId !== undefined && (typeof targetId !== 'string' || !targetId.trim())) {
      return res.status(400).json({ message: 'invalid targetId' });
    }
    const result = await simulateTampering({ targetId: targetId ? targetId.trim() : undefined });
    if (result.error) {
      return res.status(result.status || 400).json({ message: result.message, error: result.error });
    }
    return res.json(result);
  } catch (err) {
    console.error('simulate tamper error:', err);
    return res.status(500).json({ message: 'could not create tampering simulation' });
  }
};

// Restore the original record from snapshot captured before simulation
const restoreAuditTamper = async (req, res) => {
  try {
    const result = await restoreTampering();
    if (result.error) {
      return res.status(result.status || 400).json({
        message: result.message,
        error: result.error,
        verification: result.verification || null,
      });
    }
    return res.json(result);
  } catch (err) {
    console.error('restore tamper error:', err);
    return res.status(500).json({ message: 'could not restore audit tampering' });
  }
};

module.exports = {
  getAuditHistory,
  verifyAuditChain,
  getAuditDemoStatus,
  simulateAuditTamper,
  restoreAuditTamper,
};
