'use strict';

const path = require('path');
const mongoose = require('mongoose');
const { encryptPaper, decryptPaper } = require('../../crypto/paperCrypto');
const { wrapShare, unwrapShare } = require('../../crypto/shareWrap');
const Paper = require('../models/Paper');
const User = require('../models/User');
const ApproverShare = require('../models/ApproverShare');
const auditLog = require('../services/auditLog');
const { timeLockStatus } = require('../utils/timeLock');
const { canViewPaper, paperFilterFor } = require('../utils/access');

const OBJECT_ID = /^[a-f0-9]{24}$/i;
const MAX_APPROVERS = 20;
const MAX_TITLE = 200;

const bad = (res, message, status = 400) => res.status(status).json({ message });

// Strip path parts, control chars, quotes and separators; keep it short.
function safeFilename(name) {
  const base = path.basename(String(name || '')).replace(/[\x00-\x1f\x7f"'\\/<>:*?|]/g, '_').trim();
  return (base || 'paper').slice(0, 200);
}

// ---------------------------------------------------------------------
// 1. Upload — setter encrypts + splits, WRAPPED shares go to approvers
// ---------------------------------------------------------------------
const uploadPaper = async (req, res) => {
  let paper = null;
  try {
    const body = req.body || {};
    if (!req.file) return bad(res, 'file is required');

    // ---- title
    const title = typeof body.title === 'string' ? body.title.trim() : '';
    if (!title || title.length > MAX_TITLE) return bad(res, `title is required (max ${MAX_TITLE} characters)`);

    // ---- approvers: valid, unique, exist, right role
    let approverIds;
    try { approverIds = JSON.parse(body.approverIds || '[]'); } catch { return bad(res, 'approverIds must be valid JSON'); }
    if (!Array.isArray(approverIds) || approverIds.length < 2 || approverIds.length > MAX_APPROVERS) {
      return bad(res, `approverIds must be an array of 2 to ${MAX_APPROVERS} user ids`);
    }
    if (!approverIds.every((id) => typeof id === 'string' && OBJECT_ID.test(id))) {
      return bad(res, 'approverIds contains an invalid id');
    }
    approverIds = approverIds.map((id) => id.toLowerCase());
    if (new Set(approverIds).size !== approverIds.length) return bad(res, 'approverIds must not contain duplicates');

    const found = await User.countDocuments({ _id: { $in: approverIds }, role: { $in: ['approver', 'invigilator'] } });
    if (found !== approverIds.length) return bad(res, 'every approver must be an existing approver/invigilator account');

    // ---- threshold
    const n = approverIds.length;
    let kNum;
    if (body.k === undefined || body.k === '') kNum = Math.ceil(n / 2) + 1 > n ? n : Math.ceil(n / 2) + 1;
    else if (typeof body.k === 'string' && /^\d{1,3}$/.test(body.k)) kNum = parseInt(body.k, 10);
    else return bad(res, 'k must be an integer');
    if (kNum < 2 || kNum > n) return bad(res, `k must be between 2 and n (n=${n})`);

    // ---- exam window
    const start = new Date(body.examStartTime);
    const end = new Date(body.examEndTime);
    if (isNaN(start) || isNaN(end)) return bad(res, 'examStartTime and examEndTime must be valid dates');
    if (!(end > start)) return bad(res, 'examEndTime must be after examStartTime');
    if (end <= new Date()) return bad(res, 'examEndTime must be in the future');

    // ---- encrypt + split
    const { ciphertext, shares } = encryptPaper(req.file.buffer, n, kNum);

    paper = await Paper.create({
      title,
      originalFilename: safeFilename(req.file.originalname),
      uploadedBy: req.user.userId,
      ciphertext,
      n,
      k: kNum,
      approverIds,
      examStartTime: start,
      examEndTime: end,
      status: 'locked',
    });

    // One share per document, each wrapped under a key that is NOT in the DB.
    const shareDocs = approverIds.map((approverId, i) => ({
      paperId: paper._id,
      approverId,
      share: wrapShare(shares[i], paper._id, approverId),
    }));
    await ApproverShare.insertMany(shareDocs);

    await auditLog.appendEntry({
      action: 'PAPER_UPLOADED',
      actor: req.user.userId,
      paperId: paper._id,
      details: { title, n, k: kNum, approverCount: n },
    });

    return res.status(201).json({
      id: paper._id, title: paper.title, n, k: kNum,
      examStartTime: paper.examStartTime, examEndTime: paper.examEndTime, status: paper.status,
    });
  } catch (err) {
    console.error('upload error:', err);
    // Never leave a paper without its shares behind
    if (paper) {
      await ApproverShare.deleteMany({ paperId: paper._id }).catch(() => {});
      await Paper.deleteOne({ _id: paper._id }).catch(() => {});
    }
    return res.status(500).json({ message: 'upload failed' });
  }
};

// ---------------------------------------------------------------------
// 2. Approve — atomic, one approval per approver, ever
// ---------------------------------------------------------------------
const approvePaper = async (req, res) => {
  try {
    if (!OBJECT_ID.test(req.params.id)) return bad(res, 'paper not found', 404);
    const uid = req.user.userId;

    const paper = await Paper.findById(req.params.id).select('-ciphertext');
    if (!paper) return bad(res, 'paper not found', 404);

    if (!paper.approverIds.some((a) => a.toString() === uid)) {
      await auditLog.appendEntry({
        action: 'APPROVAL_DENIED', actor: uid, paperId: paper._id,
        details: { reason: 'not_a_designated_approver' },
      });
      return bad(res, 'you are not a designated approver for this paper', 403);
    }

    // Approvals only make sense before the paper is unlocked and before the exam window closes.
    const closedReason = paper.status === 'unlocked' ? 'already_unlocked'
      : new Date() > paper.examEndTime ? 'window_closed' : null;
    if (closedReason) {
      await auditLog.appendEntry({
        action: 'APPROVAL_DENIED', actor: uid, paperId: paper._id,
        details: { reason: closedReason },
      });
      return bad(res, closedReason === 'already_unlocked'
        ? 'this paper is already unlocked'
        : 'the exam window has closed; approvals are no longer accepted', 409);
    }

    const shareDoc = await ApproverShare.exists({ paperId: paper._id, approverId: uid });
    if (!shareDoc) return bad(res, 'no share on record for this approver — contact admin', 500);

    // Single atomic write. The guards (not already approved, not unlocked, window still open)
    // and the $push happen together in MongoDB, so parallel requests, or an unlock/window-close
    // landing between the checks above and this write, cannot slip an approval through.
    const now = new Date();
    const updated = await Paper.findOneAndUpdate(
      {
        _id: paper._id,
        approverIds: uid,
        'approvals.approverId': { $ne: uid },
        status: { $ne: 'unlocked' },
        examEndTime: { $gte: now },
      },
      { $push: { approvals: { approverId: uid, approvedAt: now } } },
      { new: true }
    ).select('-ciphertext');

    if (!updated) {
      // Work out why, so the message is accurate
      const fresh = await Paper.findById(paper._id).select('-ciphertext');
      if (fresh && fresh.hasApproved(uid)) return bad(res, 'you have already approved this paper', 409);
      return bad(res, 'this paper is no longer accepting approvals', 409);
    }

    if (updated.status === 'locked') {
      await Paper.updateOne({ _id: paper._id, status: 'locked' }, { $set: { status: 'pending_approval' } });
    }

    try {
      await auditLog.appendEntry({
        action: 'APPROVAL_SUBMITTED', actor: uid, paperId: paper._id,
        details: { approvalCount: updated.approvalCount(), threshold: updated.k },
      });
    } catch (auditErr) {
      // No approval without an audit record. Roll back so the approver can simply retry
      // (instead of seeing a 500 and then "already approved" on the next attempt).
      console.error('approve: audit append failed, rolling back approval:', auditErr.message);
      await Paper.updateOne({ _id: paper._id }, { $pull: { approvals: { approverId: uid } } }).catch(() => {});
      await Paper.updateOne(
        { _id: paper._id, status: 'pending_approval', approvals: { $size: 0 } },
        { $set: { status: 'locked' } }
      ).catch(() => {});
      return bad(res, 'approval could not be recorded, please try again', 500);
    }

    return res.json({
      approvalCount: updated.approvalCount(),
      threshold: updated.k,
      meetsThreshold: updated.meetsThreshold(),
    });
  } catch (err) {
    console.error('approve error:', err);
    return res.status(500).json({ message: 'approval failed' });
  }
};

// ---------------------------------------------------------------------
// 3. Status — only for papers the caller is allowed to see (404 otherwise)
// ---------------------------------------------------------------------
const getPaperStatus = async (req, res) => {
  try {
    if (!OBJECT_ID.test(req.params.id)) return bad(res, 'paper not found', 404);
    const paper = await Paper.findById(req.params.id).select('-ciphertext');
    if (!paper || !canViewPaper(paper, req.user)) return bad(res, 'paper not found', 404);

    return res.json({
      id: paper._id,
      title: paper.title,
      status: paper.status,
      approvalCount: paper.approvalCount(),
      threshold: paper.k,
      meetsThreshold: paper.meetsThreshold(),
      examStartTime: paper.examStartTime,
      examEndTime: paper.examEndTime,
      timeLock: timeLockStatus(paper),
    });
  } catch (err) {
    console.error('status error:', err);
    return res.status(500).json({ message: 'could not load status' });
  }
};

// ---------------------------------------------------------------------
// 4. Unlock — approvals + time-lock + unwrap shares + decrypt
// ---------------------------------------------------------------------
const unlockPaper = async (req, res) => {
  try {
    if (!OBJECT_ID.test(req.params.id)) return bad(res, 'paper not found', 404);
    const paper = await Paper.findById(req.params.id);
    if (!paper) return bad(res, 'paper not found', 404);

    if (!paper.meetsThreshold()) {
      await auditLog.appendEntry({
        action: 'UNLOCK_DENIED', actor: req.user.userId, paperId: paper._id,
        details: { reason: 'insufficient_approvals', have: paper.approvalCount(), need: paper.k },
      });
      return bad(res, 'insufficient approvals', 403);
    }

    const tl = timeLockStatus(paper);
    if (!tl.ok) {
      await auditLog.appendEntry({
        action: 'UNLOCK_DENIED', actor: req.user.userId, paperId: paper._id,
        details: { reason: tl.reason },
      });
      return bad(res, `access denied: ${tl.reason === 'too_early' ? 'exam has not started yet' : 'exam window has closed'}`, 403);
    }

    let originalFile;
    let approvedIds;
    try {
      approvedIds = [...new Set(paper.approvals.map((a) => a.approverId.toString()))];
      const shareDocs = await ApproverShare.find({ paperId: paper._id, approverId: { $in: approvedIds } });
      const shares = shareDocs.map((s) => unwrapShare(s.share, paper._id, s.approverId));
      originalFile = decryptPaper(paper.ciphertext, shares);
    } catch (err) {
      console.error('decrypt failed:', err.message);
      await auditLog.appendEntry({
        action: 'UNLOCK_DENIED', actor: req.user.userId, paperId: paper._id,
        details: { reason: 'decryption_failed' },
      });
      return bad(res, 'access denied', 403);
    }

    // Fail closed: the file is only released if the UNLOCK_SUCCESS audit entry was written.
    // Nothing has touched the response yet, so a failure here is a clean JSON 500.
    await auditLog.appendEntry({
      action: 'UNLOCK_SUCCESS', actor: req.user.userId, paperId: paper._id,
      details: { approvalCount: approvedIds.length },
    });

    // Status is derived state: keep the FIRST unlocker/time, and never let a failure here
    // block or corrupt the response (the audit log is the source of truth).
    try {
      await Paper.updateOne(
        { _id: paper._id, status: { $ne: 'unlocked' } },
        { $set: { status: 'unlocked', unlockedBy: req.user.userId, unlockedAt: new Date() } }
      );
    } catch (e) {
      console.error('unlock: could not update paper status:', e.message);
    }

    // Headers are set last, immediately before sending, so an earlier error can never
    // leave a JSON error body wearing a file-download Content-Disposition.
    res.attachment(safeFilename(paper.originalFilename)); // RFC 6266 encoding handled for us
    res.type('application/octet-stream');
    res.setHeader('Cache-Control', 'no-store');
    return res.send(originalFile);
  } catch (err) {
    console.error('unlock error:', err);
    return res.status(500).json({ message: 'unlock failed' });
  }
};

// ---------------------------------------------------------------------
// 5. List — never returns ciphertext or shares
// ---------------------------------------------------------------------
const listPapers = async (req, res) => {
  try {
    const papers = await Paper.find(paperFilterFor(req.user)).select('-ciphertext').sort({ createdAt: -1 }).lean();

    return res.json({
      papers: papers.map((p) => ({
        id: p._id,
        title: p.title,
        originalFilename: p.originalFilename,
        uploadedBy: p.uploadedBy,
        n: p.n,
        k: p.k,
        approverIds: (p.approverIds || []).map((a) => a.toString()),
        approvals: (p.approvals || []).map((a) => ({
          approverId: a.approverId.toString(),
          approvedAt: a.approvedAt,
        })),
        examStartTime: p.examStartTime,
        examEndTime: p.examEndTime,
        status: p.status,
      })),
    });
  } catch (err) {
    console.error('list papers error:', err);
    return res.status(500).json({ message: 'could not load papers' });
  }
};

module.exports = { uploadPaper, approvePaper, getPaperStatus, unlockPaper, listPapers };