import assert from 'node:assert';
import { hashPassword, comparePassword, MIN_PASSWORD_LENGTH } from '../src/utils/password.js';
import { generateToken, verifyToken, AuthTokenError, VALID_ROLES } from '../src/utils/jwt.js';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_key_minimum_32_characters_for_unit_tests';
process.env.BCRYPT_SALT_ROUNDS = '10';

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

console.log('\n[TrustVault] Running Cryptographic & JWT Auth Utilities Test Suite...\n');

// -----------------------------------------------------------------------------
// 1. Password Hashing & Verification Tests
// -----------------------------------------------------------------------------
console.log('--- 1. Password Hashing (bcrypt) ---');

await test('hashPassword rejects password shorter than minimum length', async () => {
  await assert.rejects(
    async () => await hashPassword('short'),
    new RegExp(`must be at least ${MIN_PASSWORD_LENGTH} characters`)
  );
});

await test('hashPassword generates valid bcrypt hash for valid password', async () => {
  const hash = await hashPassword('ValidP@ssw0rd!');
  assert.ok(typeof hash === 'string');
  assert.ok(hash.startsWith('$2a$') || hash.startsWith('$2b$'));
});

await test('comparePassword returns true for correct plaintext', async () => {
  const password = 'SuperSecretKey123!';
  const hash = await hashPassword(password);
  const isMatch = await comparePassword(password, hash);
  assert.strictEqual(isMatch, true);
});

await test('comparePassword returns false for incorrect plaintext', async () => {
  const password = 'SuperSecretKey123!';
  const hash = await hashPassword(password);
  const isMatch = await comparePassword('WrongPassword123!', hash);
  assert.strictEqual(isMatch, false);
});

await test('comparePassword returns false for null/empty/invalid inputs', async () => {
  assert.strictEqual(await comparePassword(null, 'somehash'), false);
  assert.strictEqual(await comparePassword('password', null), false);
  assert.strictEqual(await comparePassword('', ''), false);
});

// -----------------------------------------------------------------------------
// 2. JWT Generation & Verification Tests
// -----------------------------------------------------------------------------
console.log('\n--- 2. JWT Generation & Verification ---');

const sampleUser = {
  id: 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
  email: 'owner@trustvault.local',
  role: 'OWNER'
};

await test('generateToken creates valid JWT with user claims', async () => {
  const token = generateToken(sampleUser);
  assert.ok(typeof token === 'string' && token.split('.').length === 3);

  const decoded = verifyToken(token);
  assert.strictEqual(decoded.id, sampleUser.id);
  assert.strictEqual(decoded.email, sampleUser.email);
  assert.strictEqual(decoded.role, sampleUser.role);
  assert.ok(decoded.exp);
});

await test('generateToken validates all permissible roles (ADMIN, OWNER, VIEWER)', async () => {
  for (const role of VALID_ROLES) {
    const token = generateToken({ ...sampleUser, role });
    const decoded = verifyToken(token);
    assert.strictEqual(decoded.role, role);
  }
});

await test('generateToken rejects missing or invalid role', async () => {
  assert.throws(
    () => generateToken({ ...sampleUser, role: 'SUPERUSER' }),
    /requires a valid "role"/
  );
  assert.throws(
    () => generateToken({ ...sampleUser, role: null }),
    /requires a valid "role"/
  );
});

await test('generateToken rejects missing id or email', async () => {
  assert.throws(
    () => generateToken({ email: 'test@example.com', role: 'VIEWER' }),
    /requires a valid user "id"/
  );
  assert.throws(
    () => generateToken({ id: '123', role: 'VIEWER' }),
    /requires a valid user "email"/
  );
});

await test('verifyToken throws structured AuthTokenError on tampered token', async () => {
  const token = generateToken(sampleUser);
  const tamperedToken = token.slice(0, -6) + 'abcdef';

  try {
    verifyToken(tamperedToken);
    assert.fail('Expected verifyToken to throw on tampered token');
  } catch (err) {
    assert.ok(err instanceof AuthTokenError);
    assert.strictEqual(err.code, 'TOKEN_INVALID');
    assert.strictEqual(err.statusCode, 401);
  }
});

await test('verifyToken throws structured AuthTokenError on expired token', async () => {
  const expiredToken = generateToken(sampleUser, '1ms');

  // Wait 25ms to ensure expiration
  await new Promise((resolve) => setTimeout(resolve, 25));

  try {
    verifyToken(expiredToken);
    assert.fail('Expected verifyToken to throw on expired token');
  } catch (err) {
    assert.ok(err instanceof AuthTokenError);
    assert.strictEqual(err.code, 'TOKEN_EXPIRED');
    assert.strictEqual(err.statusCode, 401);
  }
});

await test('verifyToken throws structured AuthTokenError on missing token', async () => {
  assert.throws(
    () => verifyToken(''),
    (err) => err instanceof AuthTokenError && err.code === 'TOKEN_MISSING'
  );
  assert.throws(
    () => verifyToken(null),
    (err) => err instanceof AuthTokenError && err.code === 'TOKEN_MISSING'
  );
});

console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\x1b[32m✔ All Cryptographic & JWT Unit Validations Passed Successfully.\x1b[0m\n');
  process.exit(0);
}
