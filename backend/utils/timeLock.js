'use strict';

/**
 * Time-lock check. Per the integration guide, paperCrypto.js has no
 * concept of time — this must happen in our code, before decryptPaper
 * is ever called.
 */
function isWithinExamWindow(paper, now = new Date()) {
  return now >= paper.examStartTime && now <= paper.examEndTime;
}

function timeLockStatus(paper, now = new Date()) {
  if (now < paper.examStartTime) return { ok: false, reason: 'too_early' };
  if (now > paper.examEndTime) return { ok: false, reason: 'too_late' };
  return { ok: true, reason: null };
}

module.exports = { isWithinExamWindow, timeLockStatus };