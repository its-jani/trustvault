import assert from 'node:assert';
import app from '../src/server.js';
import { generateToken } from '../src/utils/jwt.js';
import supabase from '../src/config/supabase.js';

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

console.log('\n[TrustVault] Running Grant Delegation & Revocation Test Suite...\n');

// Ephemeral test server
const server = await new Promise((resolve) => {
  const s = app.listen(0, () => resolve(s));
});
const port = server.address().port;
const authUrl = `http://127.0.0.1:${port}/api/auth`;
const docUrl = `http://127.0.0.1:${port}/api/documents`;
const grantUrl = `http://127.0.0.1:${port}/api/grants`;

const ts = Date.now();
const ownerEmail = `grantowner-${ts}@trustvault.local`;
const viewer1Email = `grantviewer1-${ts}@trustvault.local`;
const viewer2Email = `grantviewer2-${ts}@trustvault.local`;
const adminEmail = `grantadmin-${ts}@trustvault.local`;

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

const ownerData = await registerUser(ownerEmail, 'OWNER');
const viewer1Data = await registerUser(viewer1Email, 'VIEWER');
const viewer2Data = await registerUser(viewer2Email, 'VIEWER');
const adminData = await registerUser(adminEmail, 'ADMIN');

// Mock storage buffer map for document upload/download
const testStorageMap = new Map();
const originalStorageFrom = supabase.storage.from.bind(supabase.storage);
supabase.storage.from = (bucket) => ({
  upload: async (path, buffer, options) => {
    testStorageMap.set(path, buffer);
    return { data: { path }, error: null };
  },
  download: async (path) => {
    const buffer = testStorageMap.get(path);
    if (!buffer) return { data: null, error: new Error('File not found in test storage') };
    return {
      data: {
        arrayBuffer: async () => buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
      },
      error: null
    };
  },
  remove: async (paths) => {
    for (const p of paths) testStorageMap.delete(p);
    return { data: paths, error: null };
  }
});

// Upload a document as owner for delegation tests
const fileContent = 'Sensitive financial statements 2026';
const fileBlob = new Blob([fileContent], { type: 'application/pdf' });
const formData = new FormData();
formData.append('document', fileBlob, 'confidential.pdf');
formData.append('title', 'Confidential Financials');
formData.append('category', 'Finance');

const uploadRes = await fetch(`${docUrl}/upload`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${ownerData.token}` },
  body: formData
});
const uploadJson = await uploadRes.json();
const testDocId = uploadJson.document.id;
let createdGrantId = null;

// -----------------------------------------------------------------------------
// 1. POST /api/grants Tests
// -----------------------------------------------------------------------------
console.log('--- 1. POST /api/grants (Delegation & Access Control) ---');

await test('rejects unauthenticated grant creation request (returns 401)', async () => {
  const res = await fetch(grantUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ documentId: testDocId, granteeEmail: viewer1Email })
  });
  assert.strictEqual(res.status, 401);
});

await test('unauthorized user cannot grant access to document they do not own (returns 403)', async () => {
  const res = await fetch(grantUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${viewer1Data.token}`
    },
    body: JSON.stringify({ documentId: testDocId, granteeEmail: viewer2Email })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 403);
  assert.match(data.message, /Forbidden/i);
});

await test('fails when grantee email does not exist (returns 404)', async () => {
  const res = await fetch(grantUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${ownerData.token}`
    },
    body: JSON.stringify({ documentId: testDocId, granteeEmail: 'nonexistent-user@trustvault.local' })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 404);
  assert.match(data.message, /Grantee user not found/i);
});

await test('blocks self-granting access to own document (returns 400)', async () => {
  const res = await fetch(grantUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${ownerData.token}`
    },
    body: JSON.stringify({ documentId: testDocId, granteeEmail: ownerEmail })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 400);
  assert.match(data.message, /Cannot grant document access to yourself/i);
});

await test('owner successfully creates document grant for viewer (returns 201)', async () => {
  const res = await fetch(grantUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${ownerData.token}`
    },
    body: JSON.stringify({ documentId: testDocId, granteeEmail: viewer1Email })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 201);
  assert.ok(data.grant);
  assert.strictEqual(data.grant.document_id, testDocId);
  assert.strictEqual(data.grant.grantee_id, viewer1Data.user.id);
  assert.strictEqual(data.grant.granted_to, viewer1Email);
  createdGrantId = data.grant.id;
});

await test('rejects duplicate grant creation (returns 409)', async () => {
  const res = await fetch(grantUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${ownerData.token}`
    },
    body: JSON.stringify({ documentId: testDocId, granteeEmail: viewer1Email })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 409);
  assert.match(data.message, /Access grant already exists/i);
});

await test('admin can create grant for any document (returns 201)', async () => {
  const res = await fetch(grantUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${adminData.token}`
    },
    body: JSON.stringify({ documentId: testDocId, granteeEmail: viewer2Email })
  });
  const data = await res.json();
  assert.strictEqual(res.status, 201);
  assert.strictEqual(data.grant.grantee_id, viewer2Data.user.id);
});

// -----------------------------------------------------------------------------
// 2. GET /api/grants/document/:documentId Tests
// -----------------------------------------------------------------------------
console.log('\n--- 2. GET /api/grants/document/:documentId (Listing Grants) ---');

await test('unauthorized user cannot list document grants (returns 403)', async () => {
  const res = await fetch(`${grantUrl}/document/${testDocId}`, {
    headers: { Authorization: `Bearer ${viewer1Data.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 403);
});

await test('owner successfully lists active grants with grantee details (returns 200)', async () => {
  const res = await fetch(`${grantUrl}/document/${testDocId}`, {
    headers: { Authorization: `Bearer ${ownerData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(Array.isArray(data.grants));
  assert.strictEqual(data.grants.length, 2);
  const v1Grant = data.grants.find((g) => g.grantee_id === viewer1Data.user.id);
  assert.ok(v1Grant);
  assert.strictEqual(v1Grant.grantee_email, viewer1Email);
});

await test('admin can list active grants for any document (returns 200)', async () => {
  const res = await fetch(`${grantUrl}/document/${testDocId}`, {
    headers: { Authorization: `Bearer ${adminData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(Array.isArray(data.grants));
  assert.strictEqual(data.grants.length, 2);
});

// -----------------------------------------------------------------------------
// 3. Live Access & Immediate Revocation Tests
// -----------------------------------------------------------------------------
console.log('\n--- 3. Immediate Access Revocation Enforcement ---');

await test('grantee can download document while grant is active (returns 200)', async () => {
  const res = await fetch(`${docUrl}/${testDocId}/download`, {
    headers: { Authorization: `Bearer ${viewer1Data.token}` }
  });
  assert.strictEqual(res.status, 200);
  const buf = await res.arrayBuffer();
  assert.strictEqual(Buffer.from(buf).toString('utf-8'), fileContent);
});

await test('unauthorized user cannot revoke grant (returns 403)', async () => {
  const res = await fetch(`${grantUrl}/${createdGrantId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${viewer2Data.token}` }
  });
  assert.strictEqual(res.status, 403);
});

await test('owner successfully revokes grant (returns 200)', async () => {
  const res = await fetch(`${grantUrl}/${createdGrantId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${ownerData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.strictEqual(data.grantId, createdGrantId);
});

await test('immediate revocation: grantee download is blocked with 403 immediately after revocation', async () => {
  const res = await fetch(`${docUrl}/${testDocId}/download`, {
    headers: { Authorization: `Bearer ${viewer1Data.token}` }
  });
  assert.strictEqual(res.status, 403);
});

// Clean up
supabase.storage.from = originalStorageFrom;
await new Promise((resolve) => server.close(resolve));

console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\x1b[32m✔ All Grant Delegation & Revocation Tests Passed Successfully.\x1b[0m\n');
  process.exit(0);
}
