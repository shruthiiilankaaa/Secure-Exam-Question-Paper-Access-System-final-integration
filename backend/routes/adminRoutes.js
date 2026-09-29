'use strict';

const express = require('express');
const authMiddleware = require('../middleware/authMiddleware');
const authorize = require('../middleware/roleMiddleware');
const { listUsers, setUserRole } = require('../controllers/adminController');

const router = express.Router();

// Everything under /api/admin requires a logged-in admin
router.use(authMiddleware, authorize('admin'));

router.get('/users', listUsers);
router.patch('/users/:id/role', setUserRole);

module.exports = router;
