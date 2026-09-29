'use strict';

/**
 * Signup validation rules (email domain + password strength).
 * Env is read at call time so dotenv load order never matters.
 */

const EMAIL_SHAPE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;

const PASSWORD_MIN = 10;
const PASSWORD_MAX_BYTES = 72; // bcrypt silently ignores anything past 72 bytes

function normalizeEmail(email) {
  return String(email).trim().toLowerCase();
}

// Unset  -> default to the IIIT Kottayam domain (secure by default)
// Empty  -> domain restriction switched off
function allowedDomain() {
  const raw = process.env.ALLOWED_EMAIL_DOMAIN;
  if (raw === undefined) return 'iiitkottayam.ac.in';
  return raw.trim().toLowerCase().replace(/^@/, '');
}

/** Returns an error string, or null if the (already normalized) email is fine. */
function emailProblem(email, { enforceDomain = true } = {}) {
  if (!EMAIL_SHAPE.test(email)) return 'Enter a valid email address';
  const domain = allowedDomain();
  // exact match after the single '@' -> rejects sub.domain and lookalike domains
  if (enforceDomain && domain && !email.endsWith('@' + domain)) {
    return `Only @${domain} email addresses can register`;
  }
  return null;
}

/** Returns a list of unmet requirements (empty list = password is fine). */
function passwordProblems(password, email = '') {
  const problems = [];

  if (password.length < PASSWORD_MIN) problems.push(`at least ${PASSWORD_MIN} characters`);
  if (Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_BYTES) problems.push(`at most ${PASSWORD_MAX_BYTES} bytes`);
  if (!/[A-Z]/.test(password)) problems.push('an uppercase letter');
  if (!/[a-z]/.test(password)) problems.push('a lowercase letter');
  if (!/[0-9]/.test(password)) problems.push('a number');
  if (!/[^A-Za-z0-9]/.test(password)) problems.push('a special character');

  const local = String(email).split('@')[0].toLowerCase();
  if (local.length >= 3 && password.toLowerCase().includes(local)) {
    problems.push('must not contain your email username');
  }

  return problems;
}

module.exports = { normalizeEmail, emailProblem, passwordProblems, allowedDomain, PASSWORD_MIN };
