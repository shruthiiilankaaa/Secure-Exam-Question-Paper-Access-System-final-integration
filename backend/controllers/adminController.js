'use strict';

const mongoose = require('mongoose');
const User = require('../models/User');
const auditLog = require('../services/auditLog');

// Roles an admin is allowed to hand out. "admin" is deliberately NOT in this list.
const ASSIGNABLE_ROLES = ['setter', 'approver', 'invigilator'];

// ---------------------------------------------------------------------
// GET /api/admin/users — every account (never returns password hashes)
// ---------------------------------------------------------------------
const listUsers = async (req, res) => {
  try {
    const users = await User.find()
      .select('name email role createdAt')
      .sort({ createdAt: -1 })
      .lean();

    return res.json({
      users: users.map((u) => ({
        id: u._id,
        name: u.name,
        email: u.email,
        role: u.role,
        createdAt: u.createdAt,
      })),
    });
  } catch (err) {
    console.error('list users error:', err);
    return res.status(500).json({ message: 'could not load users' });
  }
};

// ---------------------------------------------------------------------
// PATCH /api/admin/users/:id/role   body: { role }
// ---------------------------------------------------------------------
const setUserRole = async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body || {};

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ message: 'invalid user id' });
    }
    if (typeof role !== 'string' || !ASSIGNABLE_ROLES.includes(role)) {
      return res.status(400).json({ message: `role must be one of: ${ASSIGNABLE_ROLES.join(', ')}` });
    }

    // Admins can't edit themselves (also covered by the admin check below)
    if (id === String(req.user.userId)) {
      return res.status(403).json({ message: 'you cannot change your own role' });
    }

    const target = await User.findById(id);
    if (!target) return res.status(404).json({ message: 'user not found' });

    if (target.role === 'admin') {
      return res.status(403).json({ message: 'admin accounts cannot be changed here' });
    }

    const previousRole = target.role;
    target.role = role;
    target.tokenVersion += 1; // revoke every token issued under the old role
    await target.save();

    await auditLog.appendEntry({
      action: 'ROLE_ASSIGNED',
      actor: req.user.userId,
      details: { targetUserId: String(target._id), from: previousRole, to: role },
    });

    return res.json({
      user: { id: target._id, name: target.name, email: target.email, role: target.role },
    });
  } catch (err) {
    console.error('set role error:', err);
    return res.status(500).json({ message: 'could not update role' });
  }
};

module.exports = { listUsers, setUserRole, ASSIGNABLE_ROLES };
