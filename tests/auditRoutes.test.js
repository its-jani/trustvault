import assert from 'node:assert';
import app from '../src/server.js';
import { generateToken } from '../src/utils/jwt.js';
import { logAuditEvent } from '../src/utils/auditLogger.js';

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

console.log('\n[TrustVault] Running Admin Security Audit Inspection Test Suite...\n');

// Ephemeral test server
const server = await new Promise((resolve) => {
  const s = app.listen(0, () => resolve(s));
});
const port = server.address().port;
const authUrl = `http://127.0.0.1:${port}/api/auth`;
const auditUrl = `http://127.0.0.1:${port}/api/audit-logs`;

const ts = Date.now();
const adminEmail = `auditadmin-${ts}@trustvault.local`;
const ownerEmail = `auditowner-${ts}@trustvault.local`;
const viewerEmail = `auditviewer-${ts}@trustvault.local`;

const registerUser = async (email, role) => {
  const res = await fetch(`${authUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'Password123!Secure', role })
  });
  const data = await res.json();
  return {
    user: data.user,
    token: generateToken({ id: data.user.id, email: data.user.email, role: data.user.role })
  };
};

const adminData = await registerUser(adminEmail, 'ADMIN');
const ownerData = await registerUser(ownerEmail, 'OWNER');
const viewerData = await registerUser(viewerEmail, 'VIEWER');

// Seed a known audit event for filtering tests
const testAction = `TEST_AUDIT_ACTION_${ts}`;
await logAuditEvent({
  userId: adminData.user.id,
  action: testAction,
  resource: '00000000-0000-0000-0000-000000000001',
  details: { testRun: true, timestamp: ts },
  status: 'SUCCESS'
});

// -----------------------------------------------------------------------------
// 1. Authentication & RBAC Access Enforcement
// -----------------------------------------------------------------------------
console.log('--- 1. Authentication & RBAC Policy Enforcement ---');

await test('rejects request without token (returns 401)', async () => {
  const res = await fetch(auditUrl);
  assert.strictEqual(res.status, 401);
});

await test('rejects request with forged/invalid token (returns 401)', async () => {
  const res = await fetch(auditUrl, {
    headers: { Authorization: 'Bearer forged.invalid.token' }
  });
  assert.strictEqual(res.status, 401);
});

await test('rejects VIEWER role attempt to inspect audit logs (returns 403 Forbidden)', async () => {
  const res = await fetch(auditUrl, {
    headers: { Authorization: `Bearer ${viewerData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 403);
  assert.match(data.error, /denied|privilege/i);
});

await test('rejects OWNER role attempt to inspect audit logs (returns 403 Forbidden)', async () => {
  const res = await fetch(auditUrl, {
    headers: { Authorization: `Bearer ${ownerData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 403);
  assert.match(data.error, /denied|privilege/i);
});

// -----------------------------------------------------------------------------
// 2. Admin Inspection & Pagination
// -----------------------------------------------------------------------------
console.log('\n--- 2. Admin Log Query & Pagination Metadata ---');

await test('admin successfully queries audit logs with pagination metadata (returns 200)', async () => {
  const res = await fetch(`${auditUrl}?page=1&limit=10`, {
    headers: { Authorization: `Bearer ${adminData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(Array.isArray(data.data));
  assert.ok(data.count >= 1);
  assert.strictEqual(data.page, 1);
  assert.ok(data.totalPages >= 1);
  assert.ok(data.data.length <= 10);
  // Ensure timestamp and created_at alias exist on records
  assert.ok(data.data[0].timestamp);
  assert.ok(data.data[0].created_at);
});

await test('clamps limit to maximum 100 records per page', async () => {
  const res = await fetch(`${auditUrl}?limit=500`, {
    headers: { Authorization: `Bearer ${adminData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(data.data.length <= 100);
});

// -----------------------------------------------------------------------------
// 3. Filtering by Action, Actor, and Date Bounds
// -----------------------------------------------------------------------------
console.log('\n--- 3. Query Filtering (Action, Actor, Date) ---');

await test('filters logs accurately by action descriptor', async () => {
  const res = await fetch(`${auditUrl}?action=${testAction}`, {
    headers: { Authorization: `Bearer ${adminData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(data.data.length >= 1);
  for (const log of data.data) {
    assert.strictEqual(log.action, testAction);
  }
});

await test('filters logs accurately by actor_id', async () => {
  const res = await fetch(`${auditUrl}?actorId=${adminData.user.id}`, {
    headers: { Authorization: `Bearer ${adminData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(data.data.length >= 1);
  for (const log of data.data) {
    assert.strictEqual(log.actor_id, adminData.user.id);
  }
});

await test('filters logs within date range', async () => {
  const now = new Date();
  const oneHourAgo = new Date(now.getTime() - 3600 * 1000).toISOString();
  const oneHourLater = new Date(now.getTime() + 3600 * 1000).toISOString();

  const res = await fetch(`${auditUrl}?startDate=${oneHourAgo}&endDate=${oneHourLater}&action=${testAction}`, {
    headers: { Authorization: `Bearer ${adminData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(data.data.length >= 1);
});

await test('rejects malformed UUID filter parameter with 400 Bad Request', async () => {
  const res = await fetch(`${auditUrl}?actorId=not-a-valid-uuid`, {
    headers: { Authorization: `Bearer ${adminData.token}` }
  });
  assert.strictEqual(res.status, 400);
});

await test('rejects malformed date filter parameter with 400 Bad Request', async () => {
  const res = await fetch(`${auditUrl}?startDate=invalid-date-string`, {
    headers: { Authorization: `Bearer ${adminData.token}` }
  });
  assert.strictEqual(res.status, 400);
});

// Clean up
await new Promise((resolve) => server.close(resolve));

console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\x1b[32m✔ All Admin Audit Query & RBAC Tests Passed Successfully.\x1b[0m\n');
  process.exit(0);
}
