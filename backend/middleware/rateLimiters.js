'use strict';

const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = rateLimit;

const num = (v, fallback) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

const tooMany = (what) => ({ message: `Too many ${what}. Please try again later.` });

// Whole API safety net (per IP).
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: num(process.env.API_RATE_MAX, 300),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: tooMany('requests'),
});

// Failed logins per IP. Generous so a campus NAT (many students, one IP) isn't locked out.
const loginIpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: num(process.env.LOGIN_IP_RATE_MAX, 100),
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: tooMany('failed login attempts from this network'),
});

// Failed logins per (IP + target email): stops password guessing on one account.
const loginAccountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: num(process.env.LOGIN_ACCOUNT_RATE_MAX, 10),
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    return `${ipKeyGenerator(req.ip)}|${email}`;
  },
  message: tooMany('failed login attempts for this account'),
});

// Successful signups per IP per hour (rejected/invalid signups don't count).
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: num(process.env.SIGNUP_RATE_MAX, 10),
  skipFailedRequests: true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: tooMany('sign-ups from this network'),
});

// Chain verification walks the whole collection — keep it cheap to abuse-proof.
const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: num(process.env.VERIFY_RATE_MAX, 10),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: tooMany('audit verifications'),
});

module.exports = { apiLimiter, loginIpLimiter, loginAccountLimiter, signupLimiter, verifyLimiter };
