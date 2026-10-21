import assert from 'node:assert';
import { encryptBuffer, decryptBuffer, CryptoError } from '../src/utils/crypto.js';

process.env.NODE_ENV = 'test';
process.env.MASTER_ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

let passed = 0;
let failed = 0;

async function test(description, fn) {
  try {
    await fn();
    console.log(`  \x1b[32m✔\x1b[0m ${description}`);
    passed++;
  } catch (err) {
    console.error(`  \x1b[31m✖\x1b[0m ${description}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

console.log('\n[TrustVault] Running AES-256-GCM Envelope Encryption Test Suite...\n');

// -----------------------------------------------------------------------------
// 1. Encryption & Decryption Round-Trip Tests
// -----------------------------------------------------------------------------
console.log('--- 1. Round-Trip Confidentiality & Authenticity ---');

await test('encryptBuffer and decryptBuffer restore identical plaintext buffer', async () => {
  const originalData = Buffer.from('TrustVault Confidential Document Payload - Snovasys Challenge 2026', 'utf-8');
  const { encryptedBuffer, iv, authTag } = encryptBuffer(originalData);

  assert.ok(Buffer.isBuffer(encryptedBuffer));
  assert.notDeepStrictEqual(encryptedBuffer, originalData);
  assert.strictEqual(iv.length, 24); // 12 bytes * 2
  assert.strictEqual(authTag.length, 32); // 16 bytes * 2

  const decrypted = decryptBuffer(encryptedBuffer, iv, authTag);
  assert.ok(Buffer.isBuffer(decrypted));
  assert.deepStrictEqual(decrypted, originalData);
  assert.strictEqual(decrypted.toString('utf-8'), originalData.toString('utf-8'));
});

await test('successfully handles arbitrary binary data buffers', async () => {
  const randomBinary = Buffer.from([0x00, 0xff, 0x88, 0x77, 0x12, 0x34, 0xfe, 0xdc, 0xba]);
  const { encryptedBuffer, iv, authTag } = encryptBuffer(randomBinary);
  const decrypted = decryptBuffer(encryptedBuffer, iv, authTag);
  assert.deepStrictEqual(decrypted, randomBinary);
});

// -----------------------------------------------------------------------------
// 2. Initialization Vector (IV) Uniqueness Tests
// -----------------------------------------------------------------------------
console.log('\n--- 2. Initialization Vector (IV) Freshness ---');

await test('generates unique IV and distinct ciphertext for identical input across repeated calls', async () => {
  const payload = Buffer.from('Static document text to test IV uniqueness', 'utf-8');
  const ivSet = new Set();
  const cipherSet = new Set();

  for (let i = 0; i < 20; i++) {
    const { encryptedBuffer, iv } = encryptBuffer(payload);
    ivSet.add(iv);
    cipherSet.add(encryptedBuffer.toString('hex'));
  }

  assert.strictEqual(ivSet.size, 20, 'All 20 initialization vectors must be unique');
  assert.strictEqual(cipherSet.size, 20, 'All 20 ciphertexts must be distinct');
});

// -----------------------------------------------------------------------------
// 3. Tamper Resistance & Integrity Verification Tests
// -----------------------------------------------------------------------------
console.log('\n--- 3. Tamper Resistance & AEAD Authentication ---');

await test('rejects tampered ciphertext buffer with CryptoError', async () => {
  const original = Buffer.from('High-security financial report data', 'utf-8');
  const { encryptedBuffer, iv, authTag } = encryptBuffer(original);

  // Flip a byte in the encrypted ciphertext
  const tamperedBuffer = Buffer.from(encryptedBuffer);
  tamperedBuffer[0] ^= 0x01;

  assert.throws(
    () => decryptBuffer(tamperedBuffer, iv, authTag),
    (err) => err instanceof CryptoError && err.code === 'DECRYPTION_FAILED'
  );
});

await test('rejects tampered or forged authentication tag with CryptoError', async () => {
  const original = Buffer.from('Document payload for tag test', 'utf-8');
  const { encryptedBuffer, iv, authTag } = encryptBuffer(original);

  // Flip the first byte of the hex tag
  const forgedTag = (authTag[0] === '0' ? '1' : '0') + authTag.slice(1);

  assert.throws(
    () => decryptBuffer(encryptedBuffer, iv, forgedTag),
    (err) => err instanceof CryptoError && err.code === 'DECRYPTION_FAILED'
  );
});

await test('rejects tampered or mismatched IV with CryptoError', async () => {
  const original = Buffer.from('Document payload for IV test', 'utf-8');
  const { encryptedBuffer, iv, authTag } = encryptBuffer(original);

  const mismatchedIv = (iv[0] === '0' ? '1' : '0') + iv.slice(1);

  assert.throws(
    () => decryptBuffer(encryptedBuffer, mismatchedIv, authTag),
    (err) => err instanceof CryptoError && err.code === 'DECRYPTION_FAILED'
  );
});

// -----------------------------------------------------------------------------
// 4. Input Boundary & Type Validation Tests
// -----------------------------------------------------------------------------
console.log('\n--- 4. Input Validation & Boundaries ---');

await test('encryptBuffer rejects non-Buffer inputs', async () => {
  assert.throws(
    () => encryptBuffer('string not buffer'),
    (err) => err instanceof CryptoError && err.code === 'INVALID_INPUT'
  );
  assert.throws(
    () => encryptBuffer(null),
    (err) => err instanceof CryptoError && err.code === 'INVALID_INPUT'
  );
  assert.throws(
    () => encryptBuffer({ data: 'object' }),
    (err) => err instanceof CryptoError && err.code === 'INVALID_INPUT'
  );
});

await test('encryptBuffer rejects empty Buffer', async () => {
  assert.throws(
    () => encryptBuffer(Buffer.alloc(0)),
    (err) => err instanceof CryptoError && err.code === 'INVALID_INPUT'
  );
});

await test('decryptBuffer rejects invalid IV or authTag string lengths', async () => {
  const validBuf = Buffer.from('Valid', 'utf-8');
  assert.throws(
    () => decryptBuffer(validBuf, 'short_iv', '0123456789abcdef0123456789abcdef'),
    (err) => err instanceof CryptoError && err.code === 'INVALID_IV'
  );
  assert.throws(
    () => decryptBuffer(validBuf, '0123456789abcdef01234567', 'short_tag'),
    (err) => err instanceof CryptoError && err.code === 'INVALID_AUTH_TAG'
  );
});

console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\x1b[32m✔ All AES-256-GCM Envelope Encryption Tests Passed Successfully.\x1b[0m\n');
  process.exit(0);
}
