import assert from 'node:assert';
import express from 'express';
import { uploadSingleDocument, MAX_FILE_SIZE_BYTES } from '../src/middleware/upload.js';
import {
  uploadEncryptedDocument,
  downloadEncryptedDocument,
  deleteDocumentFromStorage,
  StorageError
} from '../src/services/storageService.js';
import supabase from '../src/config/supabase.js';
import env from '../src/config/env.js';

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

console.log('\n[TrustVault] Running Storage Service & Ingestion Middleware Test Suite...\n');

// -----------------------------------------------------------------------------
// 1. Multer In-Memory Ingestion & Size Limit Tests
// -----------------------------------------------------------------------------
console.log('--- 1. Multer Ingestion Middleware ---');

const testApp = express();
testApp.post('/test-upload', uploadSingleDocument, (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No document file provided.' });
  }
  return res.status(200).json({
    originalname: req.file.originalname,
    mimetype: req.file.mimetype,
    size: req.file.size,
    isBuffer: Buffer.isBuffer(req.file.buffer)
  });
});

const server = await new Promise((resolve) => {
  const s = testApp.listen(0, () => resolve(s));
});
const port = server.address().port;
const uploadUrl = `http://127.0.0.1:${port}/test-upload`;

await test('accepts valid file under 10MB and retains buffer in memory', async () => {
  const boundary = '----TrustVaultTestBoundary' + Date.now();
  const fileContent = 'Security audit document contents in memory';
  
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\n`),
    Buffer.from('Content-Disposition: form-data; name="document"; filename="report.pdf"\r\n'),
    Buffer.from('Content-Type: application/pdf\r\n\r\n'),
    Buffer.from(fileContent),
    Buffer.from(`\r\n--${boundary}--\r\n`)
  ]);

  const res = await fetch(uploadUrl, {
    method: 'POST',
    headers: {
      'Content-Type': `multipart/form-data; boundary=${boundary}`
    },
    body
  });

  const data = await res.json();
  assert.strictEqual(res.status, 200);
  assert.strictEqual(data.originalname, 'report.pdf');
  assert.strictEqual(data.mimetype, 'application/pdf');
  assert.strictEqual(data.isBuffer, true);
});

await test('rejects file exceeding 10MB limit with clean 400 error', async () => {
  const boundary = '----TrustVaultTestBoundary' + Date.now();
  // Generate 10MB + 1KB oversized buffer
  const oversizedBuffer = Buffer.alloc(MAX_FILE_SIZE_BYTES + 1024, 0x41);

  const prefix = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="giant.iso"\r\nContent-Type: application/octet-stream\r\n\r\n`
  );
  const suffix = Buffer.from(`\r\n--${boundary}--\r\n`);
  const body = Buffer.concat([prefix, oversizedBuffer, suffix]);

  const res = await fetch(uploadUrl, {
    method: 'POST',
    headers: {
      'Content-Type': `multipart/form-data; boundary=${boundary}`
    },
    body
  });

  const data = await res.json();
  assert.strictEqual(res.status, 400);
  assert.match(data.error, /exceeds maximum allowable limit/i);
});

// Close test HTTP server
await new Promise((resolve) => server.close(resolve));

// -----------------------------------------------------------------------------
// 2. Storage Service Parameter Validation Tests
// -----------------------------------------------------------------------------
console.log('\n--- 2. Storage Service Parameter Validation ---');

await test('uploadEncryptedDocument rejects invalid storagePath or empty buffer', async () => {
  await assert.rejects(
    async () => await uploadEncryptedDocument({ storagePath: '', encryptedBuffer: Buffer.from('data') }),
    (err) => err instanceof StorageError && err.code === 'INVALID_STORAGE_PATH'
  );
  await assert.rejects(
    async () => await uploadEncryptedDocument({ storagePath: 'test/path', encryptedBuffer: Buffer.alloc(0) }),
    (err) => err instanceof StorageError && err.code === 'INVALID_BUFFER'
  );
  await assert.rejects(
    async () => await uploadEncryptedDocument({ storagePath: 'test/path', encryptedBuffer: 'not a buffer' }),
    (err) => err instanceof StorageError && err.code === 'INVALID_BUFFER'
  );
});

await test('downloadEncryptedDocument rejects invalid storagePath', async () => {
  await assert.rejects(
    async () => await downloadEncryptedDocument(''),
    (err) => err instanceof StorageError && err.code === 'INVALID_STORAGE_PATH'
  );
  await assert.rejects(
    async () => await downloadEncryptedDocument(null),
    (err) => err instanceof StorageError && err.code === 'INVALID_STORAGE_PATH'
  );
});

await test('deleteDocumentFromStorage rejects invalid storagePath', async () => {
  await assert.rejects(
    async () => await deleteDocumentFromStorage(''),
    (err) => err instanceof StorageError && err.code === 'INVALID_STORAGE_PATH'
  );
});

// -----------------------------------------------------------------------------
// 3. Storage Service Engine Mock & Execution Tests
// -----------------------------------------------------------------------------
console.log('\n--- 3. Storage Service Engine Operations ---');

await test('upload, download, and delete execute correctly against storage engine', async () => {
  const mockStorageMap = new Map();
  const originalFrom = supabase.storage.from.bind(supabase.storage);

  // Install test mock wrapper on supabase.storage.from
  supabase.storage.from = (bucket) => ({
    upload: async (path, buffer, options) => {
      mockStorageMap.set(`${bucket}:${path}`, { buffer, contentType: options?.contentType });
      return { data: { path }, error: null };
    },
    download: async (path) => {
      const entry = mockStorageMap.get(`${bucket}:${path}`);
      if (!entry) {
        return { data: null, error: { message: 'Object not found' } };
      }
      return {
        data: {
          arrayBuffer: async () => entry.buffer.buffer.slice(
            entry.buffer.byteOffset,
            entry.buffer.byteOffset + entry.buffer.byteLength
          )
        },
        error: null
      };
    },
    remove: async (paths) => {
      for (const p of paths) {
        mockStorageMap.delete(`${bucket}:${p}`);
      }
      return { data: paths, error: null };
    }
  });

  try {
    const testPath = 'documents/owner-123/encrypted-doc-456.enc';
    const testBuffer = Buffer.from('Encrypted AES-256-GCM Payload Data', 'utf-8');

    // 1. Upload
    const uploadRes = await uploadEncryptedDocument({
      storagePath: testPath,
      encryptedBuffer: testBuffer,
      mimeType: 'application/octet-stream'
    });
    assert.strictEqual(uploadRes.path, testPath);

    // 2. Download
    const downloadedBuffer = await downloadEncryptedDocument(testPath);
    assert.ok(Buffer.isBuffer(downloadedBuffer));
    assert.deepStrictEqual(downloadedBuffer, testBuffer);

    // 3. Delete
    const deleteRes = await deleteDocumentFromStorage(testPath);
    assert.deepStrictEqual(deleteRes, [testPath]);

    // 4. Verify post-deletion download fails with StorageError
    await assert.rejects(
      async () => await downloadEncryptedDocument(testPath),
      (err) => err instanceof StorageError && err.code === 'DOWNLOAD_FAILED'
    );
  } finally {
    // Restore original supabase.storage.from
    supabase.storage.from = originalFrom;
  }
});

console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\x1b[32m✔ All Storage Service & Ingestion Tests Passed Successfully.\x1b[0m\n');
  process.exit(0);
}
