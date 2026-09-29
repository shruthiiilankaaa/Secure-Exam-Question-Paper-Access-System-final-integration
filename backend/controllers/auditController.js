'use strict';

const AuditLog = require('../models/AuditLog');
const Paper = require('../models/Paper');
const { verifyChain, SORT } = require('../services/auditLog');
const { paperFilterFor } = require('../utils/access');

const OBJECT_ID = /^[a-f0-9]{24}$/i;
const PRIVILEGED = new Set(['admin', 'invigilator']);

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

    return res.json(entries.map((e) => ({ ...e, index: position.get(String(e._id)) })));
  } catch (err) {
    console.error('audit history error:', err);
    return res.status(500).json({ message: 'could not load audit log' });
  }
};

// Integrity check — cached + rate-limited (see routes / service).
const verifyAuditChain = async (req, res) => {
  try {
    return res.json(await verifyChain());
  } catch (err) {
    console.error('audit verify error:', err);
    return res.status(500).json({ message: 'could not verify audit log' });
  }
};

module.exports = { getAuditHistory, verifyAuditChain };
