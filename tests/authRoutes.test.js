import assert from 'node:assert';
import app from '../src/server.js';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_key_minimum_32_characters_for_unit_tests';

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

console.log('\n[TrustVault] Running Auth Routes Integration Test Suite...\n');

// Spin up test server on ephemeral port
const server = await new Promise((resolve) => {
  const s = app.listen(0, () => resolve(s));
});
const port = server.address().port;
const baseUrl = `http://127.0.0.1:${port}/api/auth`;

const uniqueTimestamp = Date.now();
const testEmail = `test-engineer-${uniqueTimestamp}@trustvault.local`;
const testPassword = 'Password123!Secure';
let authToken = null;

// -----------------------------------------------------------------------------
// 1. POST /api/auth/register Tests
// -----------------------------------------------------------------------------
console.log('--- 1. POST /api/auth/register ---');

await test('rejects malformed email format', async () => {
  const res = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'not-an-email', password: testPassword })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 400);
  assert.match(data.error, /valid email/i);
});

await test('rejects password shorter than 8 characters', async () => {
  const res = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testEmail, password: 'short' })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 400);
  assert.match(data.error, /at least 8 characters/i);
});

await test('rejects invalid or unauthorized role parameter', async () => {
  const res = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testEmail, password: testPassword, role: 'SUPERADMIN' })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 400);
  assert.match(data.error, /invalid role/i);
});

await test('registers user successfully with 201 Created without leaking password_hash', async () => {
  const res = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: testEmail,
      password: testPassword,
      full_name: 'Test Security Engineer',
      role: 'OWNER'
    })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 201);
  assert.ok(data.user);
  assert.strictEqual(data.user.email, testEmail.toLowerCase());
  assert.strictEqual(data.user.role, 'OWNER');
  assert.strictEqual(data.user.password_hash, undefined);
});

await test('rejects duplicate registration with 409 Conflict', async () => {
  const res = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: testEmail,
      password: testPassword,
      role: 'OWNER'
    })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 409);
  assert.match(data.error, /already registered/i);
});

// -----------------------------------------------------------------------------
// 2. POST /api/auth/login Tests
// -----------------------------------------------------------------------------
console.log('\n--- 2. POST /api/auth/login ---');

await test('rejects login with missing email or password', async () => {
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testEmail })
  });
  assert.strictEqual(res.status, 400);
});

await test('returns 401 on non-existent email', async () => {
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'nonexistent-user@trustvault.local', password: testPassword })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 401);
  assert.strictEqual(data.error, 'Invalid email or password.');
});

await test('returns 401 on incorrect password', async () => {
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testEmail, password: 'WrongPassword999!' })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 401);
  assert.strictEqual(data.error, 'Invalid email or password.');
});

await test('authenticates valid credentials and returns signed JWT session', async () => {
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testEmail, password: testPassword })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(data.token);
  assert.strictEqual(typeof data.token, 'string');
  assert.strictEqual(data.user.email, testEmail.toLowerCase());
  assert.strictEqual(data.user.role, 'OWNER');
  assert.strictEqual(data.user.password_hash, undefined);
  authToken = data.token;
});

// -----------------------------------------------------------------------------
// 3. GET /api/auth/me Tests
// -----------------------------------------------------------------------------
console.log('\n--- 3. GET /api/auth/me ---');

await test('rejects request without Authorization header', async () => {
  const res = await fetch(`${baseUrl}/me`);
  assert.strictEqual(res.status, 401);
});

await test('rejects request with invalid or forged token', async () => {
  const res = await fetch(`${baseUrl}/me`, {
    headers: { Authorization: 'Bearer forged.invalid.token' }
  });
  assert.strictEqual(res.status, 401);
});

await test('returns verified identity claims with valid token', async () => {
  const res = await fetch(`${baseUrl}/me`, {
    headers: { Authorization: `Bearer ${authToken}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(data.user);
  assert.strictEqual(data.user.email, testEmail.toLowerCase());
  assert.strictEqual(data.user.role, 'OWNER');
});

// Clean up test server
await new Promise((resolve) => server.close(resolve));

console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\x1b[32m✔ All Auth Routes Integration Tests Passed Successfully.\x1b[0m\n');
  process.exit(0);
}
