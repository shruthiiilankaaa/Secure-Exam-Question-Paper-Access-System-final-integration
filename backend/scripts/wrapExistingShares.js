'use strict';

/**
 * One-off migration: wraps any legacy plaintext ApproverShare rows.
 *   npm run migrate:shares
 * Idempotent — already-wrapped rows are skipped.
 */
require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../config/db');
const { validateEnv } = require('../config/env');
const ApproverShare = require('../models/ApproverShare');
const { wrapShare, isWrapped } = require('../../crypto/shareWrap');

(async () => {
  validateEnv();
  await connectDB();
  let done = 0, skipped = 0;
  for await (const doc of ApproverShare.find()) {
    if (isWrapped(doc.share)) { skipped++; continue; }
    doc.share = wrapShare(doc.share, doc.paperId, doc.approverId);
    await doc.save();
    done++;
  }
  console.log(`Wrapped ${done} share(s); ${skipped} already wrapped.`);
  await mongoose.disconnect();
})().catch((e) => { console.error('migration failed:', e.message); process.exit(1); });
