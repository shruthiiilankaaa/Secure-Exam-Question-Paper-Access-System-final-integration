'use strict';

const crypto = require('crypto');
const gf = require('./gf256');

/**
 * Split `secret` (a Buffer) into `n` shares such that any `k` of them
 * can reconstruct it, but `k-1` reveal nothing (information-theoretic).
 *
 * Each share is: [1-byte x-coordinate][same length as secret, y-values]
 * We build one independent polynomial per byte of the secret.
 */
function split(secret, n, k) {
  if (!Buffer.isBuffer(secret)) throw new Error('secret must be a Buffer');
  if (k < 2) throw new Error('k must be >= 2');
  if (n < k) throw new Error('n must be >= k');
  if (n > 255) throw new Error('n must be <= 255 (x-coordinates are 1 byte, 0 is reserved)');

  const secretLen = secret.length;

  // x-coordinates 1..n (never 0, since f(0) = secret)
  const xs = [];
  for (let i = 1; i <= n; i++) xs.push(i);

  // shares[i] = Buffer of length secretLen (the y-values for xs[i])
  const shareBytes = xs.map(() => Buffer.alloc(secretLen));

  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    // random coefficients for degree k-1 polynomial, a0 = secret byte
    const coeffs = new Uint8Array(k);
    coeffs[0] = secret[byteIdx];
    const randomBytes = crypto.randomBytes(k - 1);
    for (let c = 1; c < k; c++) coeffs[c] = randomBytes[c - 1];

    for (let s = 0; s < n; s++) {
      const x = xs[s];
      let y = 0;
      // Horner's method: evaluate polynomial at x in GF(256)
      for (let c = k - 1; c >= 0; c--) {
        y = gf.add(gf.mul(y, x), coeffs[c]);
      }
      shareBytes[s][byteIdx] = y;
    }
  }

  // Encode each share as x-byte + y-bytes, base64 for easy storage/transport
  return shareBytes.map((yBuf, i) => {
    const combined = Buffer.concat([Buffer.from([xs[i]]), yBuf]);
    return combined.toString('base64');
  });
}

/**
 * Reconstruct the secret from an array of >= k shares (base64 strings
 * produced by split()). Order doesn't matter. Extra shares beyond k are fine.
 */
function combine(shares) {
  if (!Array.isArray(shares) || shares.length < 2) {
    throw new Error('need at least 2 shares');
  }

  const decoded = shares.map((s) => Buffer.from(s, 'base64'));
  const secretLen = decoded[0].length - 1;
  if (secretLen <= 0) throw new Error('malformed share');

  for (const d of decoded) {
    if (d.length !== secretLen + 1) throw new Error('shares have mismatched lengths');
  }

  const xs = decoded.map((d) => d[0]);
  // reject duplicate x-coordinates (corrupt/duplicate shares)
  if (new Set(xs).size !== xs.length) {
    throw new Error('duplicate share x-coordinates detected');
  }

  const secret = Buffer.alloc(secretLen);

  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    // Lagrange interpolation at x=0 for this byte position
    let result = 0;
    for (let i = 0; i < xs.length; i++) {
      const xi = xs[i];
      const yi = decoded[i][byteIdx + 1];

      let numerator = 1;
      let denominator = 1;
      for (let j = 0; j < xs.length; j++) {
        if (i === j) continue;
        const xj = xs[j];
        numerator = gf.mul(numerator, xj);        // (0 - xj) = xj in GF(256)
        denominator = gf.mul(denominator, gf.add(xi, xj)); // (xi - xj) = xi ^ xj
      }
      const lagrangeCoeff = gf.div(numerator, denominator);
      result = gf.add(result, gf.mul(yi, lagrangeCoeff));
    }
    secret[byteIdx] = result;
  }

  return secret;
}

module.exports = { split, combine };