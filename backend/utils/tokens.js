'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const ACCESS_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';
const REFRESH_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // keep in sync with REFRESH_EXPIRY default

// Refresh tokens are signed with their OWN secret, never the access-token
// secret — so an access token can never be replayed as a refresh token
// (and vice versa) even though both are JWTs.
function requireRefreshSecret() {
  const secret = process.env.JWT_REFRESH_SECRET;
  if (!secret) throw new Error('JWT_REFRESH_SECRET is not set');
  return secret;
}

function signAccessToken(user) {
  // tokenVersion IS embedded: authMiddleware rejects the token once the user's
  // tokenVersion moves on (logout, role change, refresh-reuse detection).
  // Role is intentionally NOT trusted from this token — authMiddleware
  // re-reads it from the DB on every request. The token is just proof of identity.
  // jti guarantees a fresh token even if issued in the same second as the last one.
  return jwt.sign({ userId: user._id, type: 'access', tokenVersion: user.tokenVersion || 0, jti: newJti() }, process.env.JWT_SECRET, {
    expiresIn: ACCESS_EXPIRY,
  });
}

function newJti() {
  return crypto.randomBytes(16).toString('hex');
}

function signRefreshToken(user, jti) {
  return jwt.sign(
    { userId: user._id, tokenVersion: user.tokenVersion, jti, type: 'refresh' },
    requireRefreshSecret(),
    { expiresIn: REFRESH_EXPIRY }
  );
}

function verifyRefreshToken(token) {
  return jwt.verify(token, requireRefreshSecret());
}

const REFRESH_COOKIE_NAME = 'refreshToken';

function refreshCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // requires HTTPS in prod; allows http in local dev
    sameSite: 'lax', // same-origin app (backend serves the frontend) — lax is enough, and avoids breaking top-level nav
    path: '/api/auth', // only sent to the auth routes that need it (refresh, logout)
    maxAge: REFRESH_MAX_AGE_MS,
  };
}

function setRefreshCookie(res, token) {
  res.cookie(REFRESH_COOKIE_NAME, token, refreshCookieOptions());
}

function clearRefreshCookie(res) {
  // clearCookie must be called with the SAME attributes (minus maxAge/expires) used to set it
  const { maxAge, ...opts } = refreshCookieOptions();
  res.clearCookie(REFRESH_COOKIE_NAME, opts);
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  newJti,
  verifyRefreshToken,
  setRefreshCookie,
  clearRefreshCookie,
  REFRESH_COOKIE_NAME,
};
