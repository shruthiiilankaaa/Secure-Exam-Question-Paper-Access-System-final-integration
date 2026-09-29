'use strict';

/**
 * Fail fast on missing / weak secrets. Called once from server.js (and the
 * seed scripts that touch shares) BEFORE anything else runs.
 */
const PLACEHOLDER = /change-?me|changeme|example|secret$|password/i;

function fail(msg) {
  console.error(`\n[config] ${msg}\n`);
  process.exit(1);
}

function needLong(name, min = 32) {
  const v = process.env[name];
  if (!v) fail(`${name} is not set. See backend/.env.example.`);
  if (v.length < min) fail(`${name} must be at least ${min} characters.`);
  if (PLACEHOLDER.test(v)) fail(`${name} still looks like a placeholder — generate a real random value.`);
  return v;
}

function validateEnv() {
  if (!process.env.MONGO_URI) fail('MONGO_URI is not set.');

  const a = needLong('JWT_SECRET');
  const r = needLong('JWT_REFRESH_SECRET');
  if (a === r) fail('JWT_SECRET and JWT_REFRESH_SECRET must be different.');

  needLong('AUDIT_HMAC_KEY');

  // 32 random bytes, hex (64 chars) or base64 (44 chars)
  const wrap = process.env.SHARE_WRAP_KEY;
  if (!wrap) fail('SHARE_WRAP_KEY is not set (32 random bytes, hex or base64).');
  const { loadWrapKey } = require('../../crypto/shareWrap');
  try { loadWrapKey(); } catch (e) { fail(`SHARE_WRAP_KEY invalid: ${e.message}`); }

  if (process.env.NODE_ENV === 'production' && !process.env.CORS_ORIGIN) {
    fail('CORS_ORIGIN must be set in production.');
  }
}

module.exports = { validateEnv };
