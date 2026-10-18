'use strict';

const express = require('express');
const authMiddleware = require('../middleware/authMiddleware');
const authorize = require('../middleware/roleMiddleware');
const {
  getAuditHistory,
  verifyAuditChain,
  getAuditDemoStatus,
  simulateAuditTamper,
  restoreAuditTamper,
} = require('../controllers/auditController');
const { verifyLimiter } = require('../middleware/rateLimiters');

const router = express.Router();

router.get('/', authMiddleware, getAuditHistory);
router.get('/verify', authMiddleware, verifyLimiter, verifyAuditChain);
router.get('/demo-status', authMiddleware, authorize('admin'), getAuditDemoStatus);
router.post('/simulate-tamper', authMiddleware, authorize('admin'), simulateAuditTamper);
router.post('/restore-tamper', authMiddleware, authorize('admin'), restoreAuditTamper);

module.exports = router;