'use strict';

/**
 * Who may see a given paper. Same rules as listPapers:
 * admin + invigilator -> all, setter -> own uploads, approver -> designated.
 */
function canViewPaper(paper, { userId, role }) {
  if (role === 'admin' || role === 'invigilator') return true;
  if (role === 'setter') return paper.uploadedBy.toString() === String(userId);
  if (role === 'approver') return (paper.approverIds || []).some((a) => a.toString() === String(userId));
  return false;
}

function paperFilterFor({ userId, role }) {
  if (role === 'setter') return { uploadedBy: userId };
  if (role === 'approver') return { approverIds: userId };
  return {}; // admin, invigilator
}

module.exports = { canViewPaper, paperFilterFor };
