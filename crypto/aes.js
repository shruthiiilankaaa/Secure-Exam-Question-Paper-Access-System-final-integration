'use strict';

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;   // recommended for GCM
const KEY_LEN = 32;  // 256 bits

function generateKey() {
  return crypto.randomBytes(KEY_LEN);
}

/**
 * Encrypt a Buffer with AES-256-GCM.
 * Returns a single Buffer: [iv (12 bytes)][authTag (16 bytes)][ciphertext]
 */
function encrypt(plainBuffer, key) {
  if (!Buffer.isBuffer(plainBuffer)) throw new Error('plainBuffer must be a Buffer');
  if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) {
    throw new Error(`key must be a ${KEY_LEN}-byte Buffer`);
  }

  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, authTag, ciphertext]);
}

/**
 * Decrypt a Buffer produced by encrypt().
 */
function decrypt(encryptedBuffer, key) {
  if (!Buffer.isBuffer(encryptedBuffer)) throw new Error('encryptedBuffer must be a Buffer');
  if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) {
    throw new Error(`key must be a ${KEY_LEN}-byte Buffer`);
  }
  if (encryptedBuffer.length < IV_LEN + 16) {
    throw new Error('encryptedBuffer too short to be valid');
  }

  const iv = encryptedBuffer.subarray(0, IV_LEN);
  const authTag = encryptedBuffer.subarray(IV_LEN, IV_LEN + 16);
  const ciphertext = encryptedBuffer.subarray(IV_LEN + 16);

  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(authTag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (_err) {
    // Don't leak Node's raw GCM error internals (exact failure reason,
    // stack details) to callers — collapse to one generic, safe message.
    throw new Error('decryption failed: invalid key, corrupted data, or tampered ciphertext');
  }
}

/**
 * Best-effort zeroing of a key/secret Buffer's contents.
 * Note: this cannot guarantee the data isn't copied elsewhere in memory
 * (V8/GC may have made copies), but it removes the obvious in-place copy
 * once you're done with a key. Call this after you're finished using a key.
 */
function wipe(buffer) {
  if (Buffer.isBuffer(buffer)) buffer.fill(0);
}

module.exports = { encrypt, decrypt, generateKey, wipe, KEY_LEN };