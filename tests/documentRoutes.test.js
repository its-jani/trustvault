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

console.log('\n[TrustVault] Running Document Routes & PEP Access Enforcement Test Suite...\n');

// Spin up test server on ephemeral port
const server = await new Promise((resolve) => {
  const s = app.listen(0, () => resolve(s));
});
const port = server.address().port;
const baseUrl = `http://127.0.0.1:${port}/api/documents`;

// Create mock users in database if needed, or register real users via /api/auth/register
const ts = Date.now();
const ownerEmail = `docowner-${ts}@trustvault.local`;
const viewerEmail = `docviewer-${ts}@trustvault.local`;
const adminEmail = `docadmin-${ts}@trustvault.local`;

const registerUser = async (email, role) => {
  const res = await fetch(`http://127.0.0.1:${port}/api/auth/register`, {
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
const viewerData = await registerUser(viewerEmail, 'VIEWER');
const adminData = await registerUser(adminEmail, 'ADMIN');

const originalFileContent = 'Top Secret Strategic Financial & Cryptographic Blueprint 2026';
let createdDocId = null;

// Mock storage buffer map for tests to run without depending on external cloud bucket creation
const testStorageMap = new Map();
const originalStorageFrom = supabase.storage.from.bind(supabase.storage);

supabase.storage.from = (bucket) => ({
  upload: async (path, buffer, options) => {
    testStorageMap.set(path, buffer);
    return { data: { path }, error: null };
  },
  download: async (path) => {
    const buffer = testStorageMap.get(path);
    if (!buffer) return { data: null, error: { message: 'Object not found' } };
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

// -----------------------------------------------------------------------------
// 1. POST /api/documents/upload Tests
// -----------------------------------------------------------------------------
console.log('--- 1. POST /api/documents/upload ---');

await test('rejects unauthenticated upload with 401', async () => {
  const res = await fetch(`${baseUrl}/upload`, { method: 'POST' });
  assert.strictEqual(res.status, 401);
});

await test('rejects upload with missing document file with 400', async () => {
  const res = await fetch(`${baseUrl}/upload`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerData.token}` }
  });
  assert.strictEqual(res.status, 400);
});

await test('encrypts and uploads valid document, returning 201 with metadata', async () => {
  const boundary = '----TrustVaultDocBoundary' + Date.now();
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\nFinancial_Blueprint.pdf\r\n`),
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="category"\r\n\r\nFinance\r\n`),
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="blueprint.pdf"\r\nContent-Type: application/pdf\r\n\r\n`),
    Buffer.from(originalFileContent),
    Buffer.from(`\r\n--${boundary}--\r\n`)
  ]);

  const res = await fetch(`${baseUrl}/upload`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${ownerData.token}`,
      'Content-Type': `multipart/form-data; boundary=${boundary}`
    },
    body
  });

  const data = await res.json();
  assert.strictEqual(res.status, 201);
  assert.ok(data.document);
  assert.strictEqual(data.document.title, 'Financial_Blueprint.pdf');
  assert.strictEqual(data.document.category, 'Finance');
  assert.strictEqual(data.document.owner_id, ownerData.user.id);
  createdDocId = data.document.id;
});

// -----------------------------------------------------------------------------
// 2. GET /api/documents Tests (List & Tenant Isolation)
// -----------------------------------------------------------------------------
console.log('\n--- 2. GET /api/documents (Tenant Isolation) ---');

await test('owner lists their uploaded document', async () => {
  const res = await fetch(baseUrl, {
    headers: { Authorization: `Bearer ${ownerData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.ok(Array.isArray(data.documents));
  const found = data.documents.find((d) => d.id === createdDocId);
  assert.ok(found);
  assert.strictEqual(found.owner_id, ownerData.user.id);
});

await test('unrelated viewer cannot see ungranted document', async () => {
  const res = await fetch(baseUrl, {
    headers: { Authorization: `Bearer ${viewerData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  const found = data.documents.find((d) => d.id === createdDocId);
  assert.strictEqual(found, undefined, 'Viewer must not see ungranted documents');
});

await test('admin sees all documents', async () => {
  const res = await fetch(baseUrl, {
    headers: { Authorization: `Bearer ${adminData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  const found = data.documents.find((d) => d.id === createdDocId);
  assert.ok(found);
});

// -----------------------------------------------------------------------------
// 3. GET /api/documents/:id/download (PEP Policy Enforcement)
// -----------------------------------------------------------------------------
console.log('\n--- 3. GET /api/documents/:id/download (PEP Access Control) ---');

await test('unauthorized user download attempt blocked with 403 Forbidden', async () => {
  const res = await fetch(`${baseUrl}/${createdDocId}/download`, {
    headers: { Authorization: `Bearer ${viewerData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 403);
  assert.match(data.error, /insufficient document permissions/i);
});

await test('returns 404 for non-existent document ID', async () => {
  const nonExistentId = '00000000-0000-0000-0000-000000000000';
  const res = await fetch(`${baseUrl}/${nonExistentId}/download`, {
    headers: { Authorization: `Bearer ${ownerData.token}` }
  });
  assert.strictEqual(res.status, 404);
});

await test('owner successfully downloads and decrypts document buffer in memory', async () => {
  const res = await fetch(`${baseUrl}/${createdDocId}/download`, {
    headers: { Authorization: `Bearer ${ownerData.token}` }
  });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers.get('content-type'), 'application/pdf');
  const buffer = await res.arrayBuffer();
  const text = Buffer.from(buffer).toString('utf-8');
  assert.strictEqual(text, originalFileContent);
});

await test('admin successfully downloads and decrypts document buffer', async () => {
  const res = await fetch(`${baseUrl}/${createdDocId}/download`, {
    headers: { Authorization: `Bearer ${adminData.token}` }
  });
  assert.strictEqual(res.status, 200);
  const buffer = await res.arrayBuffer();
  const text = Buffer.from(buffer).toString('utf-8');
  assert.strictEqual(text, originalFileContent);
});

// -----------------------------------------------------------------------------
// 4. DELETE /api/documents/:id Tests
// -----------------------------------------------------------------------------
console.log('\n--- 4. DELETE /api/documents/:id ---');

await test('unauthorized user cannot delete document (returns 403)', async () => {
  const res = await fetch(`${baseUrl}/${createdDocId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${viewerData.token}` }
  });
  assert.strictEqual(res.status, 403);
});

await test('owner successfully deletes document', async () => {
  const res = await fetch(`${baseUrl}/${createdDocId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${ownerData.token}` }
  });
  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.strictEqual(data.id, createdDocId);
});

await test('post-delete download returns 404', async () => {
  const res = await fetch(`${baseUrl}/${createdDocId}/download`, {
    headers: { Authorization: `Bearer ${ownerData.token}` }
  });
  assert.strictEqual(res.status, 404);
});

// Clean up
supabase.storage.from = originalStorageFrom;
await new Promise((resolve) => server.close(resolve));

console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\x1b[32m✔ All Document Routes & PEP Authorization Tests Passed Successfully.\x1b[0m\n');
  process.exit(0);
}
