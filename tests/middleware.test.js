import assert from 'node:assert';
import { generateToken } from '../src/utils/jwt.js';
import { authenticateToken } from '../src/middleware/auth.js';
import { requireRole } from '../src/middleware/rbac.js';

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

/**
 * Creates mock Express Request and Response objects.
 */
function createMockHttp({ headers = {}, user = null, ip = '127.0.0.1', path = '/api/protected' } = {}) {
  const req = {
    headers: { ...headers },
    user,
    ip,
    originalUrl: path,
    method: 'GET'
  };

  let statusCode = 200;
  let responseBody = null;

  const res = {
    status(code) {
      statusCode = code;
      return this;
    },
    json(payload) {
      responseBody = payload;
      return this;
    },
    get statusCode() {
      return statusCode;
    },
    get body() {
      return responseBody;
    }
  };

  return { req, res };
}

console.log('\n[TrustVault] Running PEP Authentication & RBAC Middleware Test Suite...\n');

// -----------------------------------------------------------------------------
// 1. authenticateToken Middleware Tests
// -----------------------------------------------------------------------------
console.log('--- 1. authenticateToken Middleware ---');

await test('returns 401 when Authorization header is absent', async () => {
  const { req, res } = createMockHttp();
  let nextCalled = false;

  await authenticateToken(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, false);
  assert.strictEqual(res.statusCode, 401);
  assert.strictEqual(res.body.error, 'Access token required.');
});

await test('returns 401 when Authorization header lacks Bearer prefix', async () => {
  const { req, res } = createMockHttp({ headers: { authorization: 'Basic dXNlcjpwYXNz' } });
  let nextCalled = false;

  await authenticateToken(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, false);
  assert.strictEqual(res.statusCode, 401);
  assert.strictEqual(res.body.error, 'Access token required.');
});

await test('returns 401 when token is tampered/invalid', async () => {
  const { req, res } = createMockHttp({ headers: { authorization: 'Bearer invalid.token.payload' } });
  let nextCalled = false;

  await authenticateToken(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, false);
  assert.strictEqual(res.statusCode, 401);
  assert.strictEqual(res.body.code, 'TOKEN_INVALID');
});

await test('returns 401 when token is expired', async () => {
  const user = { id: 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', email: 'user@vault.local', role: 'VIEWER' };
  const expiredToken = generateToken(user, '1ms');
  await new Promise((resolve) => setTimeout(resolve, 25));

  const { req, res } = createMockHttp({ headers: { authorization: `Bearer ${expiredToken}` } });
  let nextCalled = false;

  await authenticateToken(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, false);
  assert.strictEqual(res.statusCode, 401);
  assert.strictEqual(res.body.code, 'TOKEN_EXPIRED');
});

await test('attaches req.user and invokes next() on valid token', async () => {
  const user = { id: 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', email: 'owner@vault.local', role: 'OWNER' };
  const validToken = generateToken(user, '1h');

  const { req, res } = createMockHttp({ headers: { authorization: `Bearer ${validToken}` } });
  let nextCalled = false;

  await authenticateToken(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, true);
  assert.strictEqual(res.statusCode, 200);
  assert.deepStrictEqual(req.user, user);
});

// -----------------------------------------------------------------------------
// 2. requireRole Middleware Tests
// -----------------------------------------------------------------------------
console.log('\n--- 2. requireRole Middleware ---');

await test('returns 403 when req.user is missing', async () => {
  const { req, res } = createMockHttp({ user: null });
  let nextCalled = false;
  const middleware = requireRole(['ADMIN', 'OWNER']);

  await middleware(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, false);
  assert.strictEqual(res.statusCode, 403);
  assert.strictEqual(res.body.error, 'Access denied: Insufficient privileges.');
});

await test('returns 403 when user role is not authorized', async () => {
  const user = { id: 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', email: 'viewer@vault.local', role: 'VIEWER' };
  const { req, res } = createMockHttp({ user });
  let nextCalled = false;
  const middleware = requireRole(['ADMIN', 'OWNER']);

  await middleware(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, false);
  assert.strictEqual(res.statusCode, 403);
  assert.strictEqual(res.body.error, 'Access denied: Insufficient privileges.');
});

await test('invokes next() when user role matches authorized roles array', async () => {
  const user = { id: 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', email: 'owner@vault.local', role: 'OWNER' };
  const { req, res } = createMockHttp({ user });
  let nextCalled = false;
  const middleware = requireRole(['ADMIN', 'OWNER']);

  await middleware(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, true);
  assert.strictEqual(res.statusCode, 200);
});

await test('invokes next() when single role string matches user role', async () => {
  const user = { id: 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', email: 'admin@vault.local', role: 'ADMIN' };
  const { req, res } = createMockHttp({ user });
  let nextCalled = false;
  const middleware = requireRole('ADMIN');

  await middleware(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, true);
  assert.strictEqual(res.statusCode, 200);
});

console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\x1b[32m✔ All PEP Authentication & RBAC Middleware Tests Passed Successfully.\x1b[0m\n');
  process.exit(0);
}
