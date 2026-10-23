import assert from 'node:assert';
import app from '../src/server.js';
import { sanitizeValue } from '../src/middleware/validator.js';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_key_minimum_32_characters_for_unit_tests';
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

console.log('\n[TrustVault] Running Rate Limiter, Health & Sanitization Test Suite...\n');

// Spin up ephemeral test server
const server = await new Promise((resolve) => {
  const s = app.listen(0, () => resolve(s));
});
const port = server.address().port;
const baseUrl = `http://127.0.0.1:${port}`;

// -----------------------------------------------------------------------------
// 1. Public Health Check Endpoint (GET /health)
// -----------------------------------------------------------------------------
console.log('--- 1. Public Health Check (GET /health) ---');

await test('returns 200 OK with healthy status, timestamp, and uptime', async () => {
  const res = await fetch(`${baseUrl}/health`);
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.strictEqual(data.status, 'healthy');
  assert.ok(data.timestamp);
  assert.strictEqual(typeof data.uptime, 'number');
});

// -----------------------------------------------------------------------------
// 2. Input Sanitization Validator
// -----------------------------------------------------------------------------
console.log('\n--- 2. Input Sanitization Middleware ---');

await test('strips HTML tags, script blocks, null bytes, and javascript pseudo-protocols', () => {
  const dirtyString = '<script>alert("XSS")</script>Hello <b>World</b>\0javascript:doEvil()';
  const cleanString = sanitizeValue(dirtyString);
  assert.strictEqual(cleanString, 'Hello WorlddoEvil()');
});

await test('recursively sanitizes nested objects and arrays', () => {
  const dirtyPayload = {
    title: '<script>steal()</script>Document Title',
    tags: ['<b>finance</b>', '<i>audit</i>'],
    nested: {
      field: '<iframe src="evil.com"></iframe>Clean content\0'
    }
  };
  const cleanPayload = sanitizeValue(dirtyPayload);
  assert.strictEqual(cleanPayload.title, 'Document Title');
  assert.deepStrictEqual(cleanPayload.tags, ['finance', 'audit']);
  assert.strictEqual(cleanPayload.nested.field, 'Clean content');
});

// -----------------------------------------------------------------------------
// 3. Rate Limiting Enforcement
// -----------------------------------------------------------------------------
console.log('\n--- 3. Rate Limiting Protection (429 Too Many Requests) ---');

await test('authRateLimiter blocks requests exceeding 10 attempts on login with 429 Too Many Requests', async () => {
  let hit429 = false;
  let lastStatus = 0;
  let responseData = null;

  // Execute 12 consecutive requests with x-test-rate-limit header
  for (let i = 0; i < 12; i++) {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-test-rate-limit': 'true'
      },
      body: JSON.stringify({ email: `ratelimit-${i}@trustvault.local`, password: 'WrongPassword123!' })
    });
    lastStatus = res.status;
    if (res.status === 429) {
      hit429 = true;
      responseData = await res.json();
      break;
    }
  }

  assert.strictEqual(hit429, true, 'Rate limiter must trigger HTTP 429 after exceeding limit');
  assert.strictEqual(lastStatus, 429);
  assert.match(responseData.error, /too many authentication attempts/i);
});

// Clean up
await new Promise((resolve) => server.close(resolve));

console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\x1b[32m✔ All Rate Limiting, Health & Sanitization Tests Passed Successfully.\x1b[0m\n');
  process.exit(0);
}
