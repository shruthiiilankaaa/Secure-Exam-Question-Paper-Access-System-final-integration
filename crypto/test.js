'use strict';

const assert = require('assert');
const { encryptPaper, decryptPaper } = require('./paperCrypto');
const shamir = require('./shamir');
const aes = require('./aes');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`✗ ${name}`);
    console.log(`  ${err.message}`);
    failed++;
  }
}

// --- AES round trip ---
test('AES: encrypt/decrypt round trip', () => {
  const key = aes.generateKey();
  const data = Buffer.from('hello world, this is a secret file');
  const enc = aes.encrypt(data, key);
  const dec = aes.decrypt(enc, key);
  assert.strictEqual(dec.toString(), data.toString());
});

test('AES: wrong key fails to decrypt', () => {
  const key = aes.generateKey();
  const wrongKey = aes.generateKey();
  const data = Buffer.from('secret');
  const enc = aes.encrypt(data, key);
  assert.throws(() => aes.decrypt(enc, wrongKey));
});

test('AES: tampered ciphertext fails auth check', () => {
  const key = aes.generateKey();
  const data = Buffer.from('secret data here');
  const enc = aes.encrypt(data, key);
  enc[enc.length - 1] ^= 0xff; // flip a bit in ciphertext
  assert.throws(() => aes.decrypt(enc, key));
});

// --- Shamir round trip ---
test('Shamir: split/combine with exact threshold', () => {
  const secret = Buffer.from('this is a 32-byte secret key!!!!');
  assert.strictEqual(secret.length, 32);
  const shares = shamir.split(secret, 5, 3);
  const recovered = shamir.combine(shares.slice(0, 3));
  assert.strictEqual(recovered.toString('hex'), secret.toString('hex'));
});

test('Shamir: combine works with any 3-of-5 subset', () => {
  const secret = Buffer.from('another-32-byte-secret-key-here');
  const shares = shamir.split(secret, 5, 3);
  const subsets = [
    [0, 1, 2], [0, 1, 3], [0, 1, 4], [1, 2, 3], [2, 3, 4], [0, 3, 4]
  ];
  for (const idxs of subsets) {
    const chosen = idxs.map((i) => shares[i]);
    const recovered = shamir.combine(chosen);
    assert.strictEqual(recovered.toString('hex'), secret.toString('hex'));
  }
});

test('Shamir: fewer than k shares does NOT reconstruct correctly', () => {
  const secret = Buffer.from('yet-another-32-byte-secret-key!');
  const shares = shamir.split(secret, 5, 3);
  // Only 2 shares (below threshold of 3) — should NOT equal original.
  const recovered = shamir.combine(shares.slice(0, 2));
  assert.notStrictEqual(recovered.toString('hex'), secret.toString('hex'));
});

test('Shamir: extra shares beyond k still work', () => {
  const secret = Buffer.from('12345678901234567890123456789012');
  const shares = shamir.split(secret, 6, 3);
  const recovered = shamir.combine(shares); // all 6
  assert.strictEqual(recovered.toString('hex'), secret.toString('hex'));
});

test('Shamir: rejects duplicate shares', () => {
  const secret = Buffer.from('12345678901234567890123456789012');
  const shares = shamir.split(secret, 5, 3);
  assert.throws(() => shamir.combine([shares[0], shares[0], shares[1]]));
});

test('Shamir: rejects invalid params (k > n)', () => {
  const secret = Buffer.from('12345678901234567890123456789012');
  assert.throws(() => shamir.split(secret, 2, 3));
});

// --- Full paper flow ---
test('paperCrypto: full encryptPaper/decryptPaper round trip (3-of-5)', () => {
  const file = Buffer.from('This is the full contents of an important file.\nLine 2.\n');
  const { ciphertext, shares } = encryptPaper(file, 5, 3);
  assert.strictEqual(shares.length, 5);
  const recovered = decryptPaper(ciphertext, [shares[1], shares[3], shares[4]]);
  assert.strictEqual(recovered.toString(), file.toString());
});

test('paperCrypto: fails to decrypt with insufficient shares', () => {
  const file = Buffer.from('another important file');
  const { ciphertext, shares } = encryptPaper(file, 5, 3);
  assert.throws(() => {
    const recovered = decryptPaper(ciphertext, [shares[0], shares[1]]);
    // even if it doesn't throw during combine, AES auth tag check should fail
    if (recovered.toString() === file.toString()) {
      throw new Error('SECURITY BUG: reconstructed with too few shares!');
    }
  });
});

test('paperCrypto: works with binary (non-text) file data', () => {
  const file = Buffer.from(Array.from({ length: 1000 }, (_, i) => i % 256));
  const { ciphertext, shares } = encryptPaper(file, 4, 2);
  const recovered = decryptPaper(ciphertext, [shares[0], shares[2]]);
  assert.strictEqual(Buffer.compare(recovered, file), 0);
});

test('paperCrypto: 2-of-2 threshold works (edge case, k=n)', () => {
  const file = Buffer.from('edge case file');
  const { ciphertext, shares } = encryptPaper(file, 2, 2);
  const recovered = decryptPaper(ciphertext, shares);
  assert.strictEqual(recovered.toString(), file.toString());
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);