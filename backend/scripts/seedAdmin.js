'use strict';

/**
 * Creates the first admin account (signup can never create admins).
 *
 *   1. put ADMIN_NAME (optional), ADMIN_EMAIL and ADMIN_PASSWORD in backend/.env
 *   2. run:  npm run seed:admin
 *
 * If a user with ADMIN_EMAIL already exists, it is promoted to admin
 * (its password is left untouched).
 */

require('dotenv').config();

const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const connectDB = require('../config/db');
const User = require('../models/User');
const { normalizeEmail, emailProblem, passwordProblems } = require('../utils/validators');

(async () => {
  const name = (process.env.ADMIN_NAME || 'Administrator').trim();
  const rawEmail = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;

  if (!rawEmail || !password) {
    console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD in backend/.env first.');
    process.exit(1);
  }

  const email = normalizeEmail(rawEmail);
  // Domain restriction does not apply to the bootstrap admin, but the shape and password rules do.
  const emailError = emailProblem(email, { enforceDomain: false });
  if (emailError) {
    console.error(`ADMIN_EMAIL: ${emailError}`);
    process.exit(1);
  }
  const problems = passwordProblems(password, email);
  if (problems.length) {
    console.error(`ADMIN_PASSWORD requirements not met: ${problems.join(', ')}`);
    process.exit(1);
  }

  if (password === 'ChangeThis!Now2026') {
    if (process.env.NODE_ENV === 'production') {
      console.error('ADMIN_PASSWORD is still the placeholder from .env.example — set a real one.');
      process.exit(1);
    }
    console.warn('WARNING: ADMIN_PASSWORD is still the placeholder from .env.example — change it before real use.');
  }

  await connectDB();

  const existing = await User.findOne({ email });
  if (existing) {
    if (existing.role === 'admin') {
      console.log(`${email} is already an admin. Nothing to do.`);
    } else {
      existing.role = 'admin';
      existing.tokenVersion += 1;        // role changed -> revoke tokens issued under the old role
      existing.currentRefreshJti = null;
      await existing.save();
      console.log(`Existing user ${email} promoted to admin.`);
    }
  } else {
    await User.create({ name, email, passwordHash: await bcrypt.hash(password, 10), role: 'admin' });
    console.log(`Admin account created: ${email}`);
  }

  await mongoose.disconnect();
})().catch((err) => {
  console.error('seed:admin failed:', err.message);
  process.exit(1);
});
