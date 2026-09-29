'use strict';

const mongoose = require('mongoose');

const approverShareSchema = new mongoose.Schema(
  {
    paperId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Paper',
      required: true,
    },
    approverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    share: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

// One share per approver per paper
approverShareSchema.index({ paperId: 1, approverId: 1 }, { unique: true });

module.exports = mongoose.model('ApproverShare', approverShareSchema);