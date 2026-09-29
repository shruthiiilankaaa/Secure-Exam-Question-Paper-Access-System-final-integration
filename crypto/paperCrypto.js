'use strict';

const aes = require('./aes');
const shamir = require('./shamir');

/**
 * Encrypt a file buffer and split its AES key into Shamir shares.
 *
 * @param {Buffer} fileBuffer - raw file contents
 * @param {number} n - total number of shares to generate
 * @param {number} k - threshold number of shares needed to reconstruct
 * @returns {{ ciphertext: Buffer, shares: string[] }}
 */
function encryptPaper(fileBuffer, n, k) {
  const key = aes.generateKey();
  try {
    const ciphertext = aes.encrypt(fileBuffer, key);
    const shares = shamir.split(key, n, k);
    return { ciphertext, shares };
  } finally {
    // Best-effort: zero the raw key buffer now that it's been split into
    // shares and no longer needed in this form.
    aes.wipe(key);
  }
}

/**
 * Reconstruct the AES key from >= k shares and decrypt the ciphertext.
 *
 * @param {Buffer} ciphertext - output of encryptPaper
 * @param {string[]} shares - at least k of the shares from encryptPaper
 * @returns {Buffer} original file contents
 */
function decryptPaper(ciphertext, shares) {
  const key = shamir.combine(shares);
  try {
    if (key.length !== aes.KEY_LEN) {
      throw new Error('reconstructed key has wrong length — wrong/corrupted shares?');
    }
    return aes.decrypt(ciphertext, key);
  } finally {
    // Best-effort: zero the reconstructed key buffer once decryption is done.
    aes.wipe(key);
  }
}

module.exports = { encryptPaper, decryptPaper };