'use strict';

const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  actor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  paperId: { type: mongoose.Schema.Types.ObjectId, ref: 'Paper', default: null },
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  timestamp: { type: Date, required: true },
  prevHash: { type: String, required: true },
  hash: { type: String, required: true },
  // v2 entries: HMAC-SHA256 chain + strictly increasing seq. Entries without
  // `v` are legacy plain-SHA256 rows written before the patch.
  v: { type: Number },
  seq: { type: Number },
});

// Unique seq => two concurrent appends can't both claim the same chain slot.
auditLogSchema.index({ seq: 1 }, { unique: true, sparse: true });

module.exports = mongoose.model('AuditLog', auditLogSchema);
