'use strict';

const express = require('express');
const multer = require('multer');

const authMiddleware = require('../middleware/authMiddleware');
const authorize = require('../middleware/roleMiddleware');
const { uploadPaper, approvePaper, getPaperStatus, unlockPaper, listPapers } = require('../controllers/paperController');

const router = express.Router();
// Ciphertext is stored inline in one MongoDB document (16 MB cap) and the file is
// buffered in RAM, so keep uploads small. Override with MAX_UPLOAD_MB (max 15).
const MAX_UPLOAD_MB = Math.min(parseInt(process.env.MAX_UPLOAD_MB, 10) || 10, 15);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1, fields: 10, parts: 12, fieldSize: 64 * 1024 },
});

router.get('/', authMiddleware, listPapers);
router.post('/', authMiddleware, authorize('setter'), upload.single('file'), uploadPaper);
router.post('/:id/approve', authMiddleware, authorize('approver', 'invigilator'), approvePaper);
router.get('/:id/status', authMiddleware, getPaperStatus);
router.post('/:id/unlock', authMiddleware, authorize('invigilator'), unlockPaper);

module.exports = router;