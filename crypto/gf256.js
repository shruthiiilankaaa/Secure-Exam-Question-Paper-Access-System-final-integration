'use strict';

/**
 * GF(2^8) arithmetic using the AES reduction polynomial (0x11b).
 * This is the standard field used for Shamir's Secret Sharing over bytes.
 */

// Precompute exp/log tables for fast multiply/divide.
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

(function buildTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    // multiply x by generator 3 in GF(256), reducing by 0x11b
    x = x ^ (x << 1) ^ ((x & 0x80) ? 0x1b : 0);
    x &= 0xff;
  }
  for (let i = 255; i < 512; i++) {
    EXP[i] = EXP[i - 255];
  }
})();

function add(a, b) {
  // addition/subtraction in GF(2^8) is XOR
  return a ^ b;
}

function mul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function inv(a) {
  if (a === 0) throw new Error('Cannot invert zero in GF(256)');
  return EXP[255 - LOG[a]];
}

function div(a, b) {
  if (b === 0) throw new Error('Division by zero in GF(256)');
  if (a === 0) return 0;
  return EXP[(LOG[a] + 255 - LOG[b]) % 255];
}

module.exports = { add, mul, inv, div };