'use strict';

/**
 * Wipes the users collection and creates a fresh, ready-to-use set:
 * one admin (from .env) plus a handful of setter/approver/invigilator
 * test accounts — no "pending" step needed for these.
 *
 * Run:  npm run seed:users
 *
 * Customize the list below, or override with a JSON file:
 *   npm run seed:users -- --file=./my-users.json
 *   (file format: an array of {name, email, password, role})
 *
 * Passwords: a fresh random one per run (printed once at the end), or SEED_PASSWORD=...
 * Refuses to run when NODE_ENV=production unless --force-production is given.
 *
 * WARNING: this DELETES every existing user (and, transitively, every
 * paper's approverIds will point at accounts that no longer exist —
 * fine for a clean test run, not for a database you care about).
 */

require('dotenv').config();

const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const connectDB = require('../config/db');
const User = require('../models/User');
const { normalizeEmail, emailProblem, passwordProblems } = require('../utils/validators');

const EXAMPLE_ADMIN_PASSWORD = 'ChangeThis!Now2026'; // the placeholder shipped in .env.example

// Safety: this script DELETES every user. Never let it run against production by accident.
if (process.env.NODE_ENV === 'production' && !process.argv.includes('--force-production')) {
  console.error('Refusing to run seed:users with NODE_ENV=production (it wipes ALL users).');
  console.error('If you really mean it, add --force-production.');
  process.exit(1);
}

// Random password per run instead of a published one. Guaranteed to satisfy the
// password rules. Set SEED_PASSWORD in the environment to pin your own.
function generatePassword() {
  const pick = (chars) => chars[crypto.randomInt(chars.length)];
  const U = 'ABCDEFGHJKLMNPQRSTUVWXYZ', L = 'abcdefghijkmnopqrstuvwxyz', D = '23456789', S = '!@#$%^&*-_=+';
  const all = U + L + D + S;
  const chars = [pick(U), pick(L), pick(D), pick(S)];
  while (chars.length < 20) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i--) { // Fisher–Yates shuffle
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}
const DEFAULT_PASSWORD = process.env.SEED_PASSWORD || generatePassword();
const domain = process.env.ALLOWED_EMAIL_DOMAIN || 'iiitkottayam.ac.in';

// Default seed set — edit freely. Each needs name, email, password, role.
const DEFAULT_USERS = [
  { name: 'Setter One', email: `setter1@${domain}`, password: DEFAULT_PASSWORD, role: 'setter' },
  { name: 'Approver One', email: `approver1@${domain}`, password: DEFAULT_PASSWORD, role: 'approver' },
  { name: 'Approver Two', email: `approver2@${domain}`, password: DEFAULT_PASSWORD, role: 'approver' },
  { name: 'Invigilator One', email: `invigilator1@${domain}`, password: DEFAULT_PASSWORD, role: 'invigilator' },
  { name: 'Pending Example', email: `pendingexample@${domain}`, password: DEFAULT_PASSWORD, role: 'pending' },
];

function loadUserList() {
  const fileArg = process.argv.find((a) => a.startsWith('--file='));
  if (!fileArg) return DEFAULT_USERS;
  const path = fileArg.slice('--file='.length);
  const raw = JSON.parse(fs.readFileSync(path, 'utf8'));
  if (!Array.isArray(raw)) throw new Error('--file must contain a JSON array of {name, email, password, role}');
  return raw;
}

const VALID_ROLES = ['setter', 'approver', 'invigilator', 'admin', 'pending'];

(async () => {
  const users = loadUserList();

  // Validate everything BEFORE touching the database, so a typo doesn't
  // leave you with an empty users collection and nothing to show for it.
  const errors = [];
  const seenEmails = new Set();
  for (const [i, u] of users.entries()) {
    const label = `#${i + 1} (${u.email || u.name || '?'})`;
    if (!u.name || typeof u.name !== 'string') errors.push(`${label}: missing name`);
    if (!u.role || !VALID_ROLES.includes(u.role)) errors.push(`${label}: role must be one of ${VALID_ROLES.join(', ')}`);
    if (typeof u.email !== 'string') { errors.push(`${label}: missing email`); continue; }
    const email = normalizeEmail(u.email);
    u.email = email;
    if (seenEmails.has(email)) errors.push(`${label}: duplicate email in the seed list`);
    seenEmails.add(email);
    const eErr = emailProblem(email, { enforceDomain: u.role !== 'admin' });
    if (eErr) errors.push(`${label}: ${eErr}`);
    const pErr = passwordProblems(u.password || '', email);
    if (pErr.length) errors.push(`${label}: password needs ${pErr.join(', ')}`);
  }
  if (errors.length) {
    console.error('Fix these before seeding:\n' + errors.map((e) => '  - ' + e).join('\n'));
    process.exit(1);
  }

  await connectDB();

  const { deletedCount } = await User.deleteMany({});
  console.log(`Cleared ${deletedCount} existing user(s).`);

  // Also (re)create the bootstrap admin from .env, so the DB is usable right away
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminPassword === EXAMPLE_ADMIN_PASSWORD) {
    console.warn('WARNING: ADMIN_PASSWORD is still the placeholder from .env.example — change it.');
  }
  if (adminEmail && adminPassword) {
    const email = normalizeEmail(adminEmail);
    if (!users.some((u) => u.email === email)) {
      const err = emailProblem(email, { enforceDomain: false }) || passwordProblems(adminPassword, email).join(', ');
      if (!emailProblem(email, { enforceDomain: false }) && !passwordProblems(adminPassword, email).length) {
        await User.create({
          name: process.env.ADMIN_NAME || 'Administrator',
          email,
          passwordHash: await bcrypt.hash(adminPassword, 10),
          role: 'admin',
        });
        console.log(`Created admin: ${email}`);
      } else {
        console.log(`Skipped .env admin (${err || 'invalid'}) — add it to the seed list yourself if needed.`);
      }
    }
  }

  for (const u of users) {
    await User.create({
      name: u.name.trim(),
      email: u.email,
      passwordHash: await bcrypt.hash(u.password, 10),
      role: u.role,
    });
    console.log(`Created ${u.role.padEnd(11)} ${u.email}`);
  }

  console.log(`\nDone. ${users.length} seeded user(s).`);
  if (users.some((u) => u.password === DEFAULT_PASSWORD)) {
    console.log(`Password for the default test accounts (shown once, different every run): ${DEFAULT_PASSWORD}`);
    console.log('(pin your own with SEED_PASSWORD=..., or pass --file with per-user passwords)');
  }

  await mongoose.disconnect();
})().catch((err) => {
  console.error('seed:users failed:', err.message);
  process.exit(1);
});
