'use strict';

const express = require('express');
const authMiddleware = require('../middleware/authMiddleware');
const { getAuditHistory, verifyAuditChain } = require('../controllers/auditController');
const { verifyLimiter } = require('../middleware/rateLimiters');

const router = express.Router();

router.get('/', authMiddleware, getAuditHistory);
router.get('/verify', authMiddleware, verifyLimiter, verifyAuditChain);

module.exports = router;