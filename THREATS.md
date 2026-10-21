# TrustVault — Threat Modeling & Security Risk Register (`THREATS.md`)

## 1. Overview & Threat Modeling Methodology
TrustVault is architected under the principle of **Zero Trust**: *Never trust, always verify*. The system assumes the client environment is fully untrusted and adversarial. All authorization decisions are strictly evaluated on the server-side Policy Enforcement Point (PEP), backed by immutable audit trails and live database state.

This register employs the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) and maps risks to the **OWASP Top 10 API Security Risks (2023)**.

---

## Threat Matrix Summary

| Threat ID | Threat Name | STRIDE Category | OWASP API | Severity | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TV-01** | Audit Trail Alteration & Tampering | Tampering, Repudiation | API8: Security Misconfiguration | **CRITICAL** | **Mitigated (DB Trigger & Hash Chain)** |
| **TV-02** | Path Traversal & Static Storage Exposure | Tampering, Info Disclosure, EoP | API1: Broken Object Level Auth (BOLA) / API3: Broken Object Property | **CRITICAL** | **Mitigated (Virtual UUID Storage & Stream Proxy)** |
| **TV-03** | Weak Signing Key & JWT Forgery | Spoofing, Elevation of Privilege | API2: Broken Authentication | **HIGH** | **Mitigated (Min 32-char Secret & Fail-Fast)** |
| **TV-04** | Credential Stuffing & Brute-Forcing | Spoofing | API2: Broken Authentication | **HIGH** | **Mitigated (Bcrypt Salt 12 & Rate Limit Plan)** |
| **TV-05** | Account Enumeration Oracle | Information Disclosure | API2: Broken Authentication | **MEDIUM** | **Mitigated (Uniform Error Responses)** |
| **TV-06** | Privilege Escalation at Registration | Elevation of Privilege | API5: Broken Function Level Auth | **HIGH** | **Mitigated (Whitelist & Default VIEWER)** |
| **TV-07** | BOLA on Document Download/Delete | Elevation of Privilege, Info Disclosure | API1: Broken Object Level Auth (BOLA) | **CRITICAL** | **Mitigated (Three-Gate PEP Check + Audit Log)** |
| **TV-08** | AES-GCM IV Reuse & Auth Tag Strip | Tampering, Information Disclosure | API8: Security Misconfiguration | **CRITICAL** | **Mitigated (Atomic Envelope, Mandatory Auth Tag)** |
| **TV-09** | Malicious File Upload & Oversized Payload | Tampering, Denial of Service, EoP | API4: Unrestricted Resource Consumption | **HIGH** | **Mitigated (10MB RAM Limit, UUID Paths, Private Bucket)** |

---

## 2. Threat Vector 1: Audit Trail Alteration & Forensic Erasure (TV-01)

### A. Threat Description & Threat Actor
An adversary (such as an external attacker with compromised API credentials, an insider threat, or an attacker exploiting an SQL injection vulnerability) attempts to alter or delete audit log entries. The objective is to erase evidence of unauthorized access, privilege escalation, or document exfiltration, creating repudiation.

* **STRIDE Category:** Tampering, Repudiation.
* **OWASP API Classification:** API8: Security Misconfiguration / API10: Unsafe Consumption of APIs.
* **Risk Severity:** **CRITICAL** (10/10 CVSS Vector).
* **Challenge Zero-Tolerance Rule:** *Rule #3: Allowing UPDATE or DELETE SQL queries against `audit_logs`.*

### B. Attack Scenarios
1. **Direct Query Injection:** An attacker compromises a database connection or finds a dynamic SQL query vector and executes:
   ```sql
   DELETE FROM audit_logs WHERE actor_id = 'compromised-uuid';
   ```
2. **Metadata Sanitization / Rewriting:** An attacker attempts to overwrite historical logs with benign event labels:
   ```sql
   UPDATE audit_logs SET action = 'DOCUMENT_READ_GRANTED' WHERE action = 'ACCESS_DENIED_UNAUTHORIZED';
   ```
3. **Cascade Deletion:** An attacker deletes a compromised user or document entity, triggering an implicit `ON DELETE CASCADE` that purges associated audit records.

### C. Defense-in-Depth Mitigation Strategy
1. **PostgreSQL PL/pgSQL Immutability Trigger:**
   * A database trigger `prevent_audit_log_alteration` is attached to `BEFORE UPDATE OR DELETE ON audit_logs`.
   * Any update or delete operation raises an uncatchable exception `55000: TRUSTVAULT_SECURITY_VIOLATION`. This operates independently of application code logic.
2. **Cryptographic Hash Chaining (`previous_hash`, `current_hash`):**
   * Each audit log row computes SHA-256 over `(id + timestamp + actor_id + action + document_id + details + previous_hash)`.
   * Deleting or inserting any intermediate row breaks the cryptographic chain, making tampering detectable.
3. **Decoupled Foreign Key Cascade Policies:**
   * Foreign keys on `audit_logs` (`actor_id`, `document_id`) utilize `ON DELETE SET NULL`. Deletion of a user or document does not purge the forensic audit trail.
4. **Authoritative Policy Enforcement Point (PEP):**
   * Express middleware intercepts all access attempts and writes `ACCESS_DENIED` logs directly to `audit_logs` before returning `403 Forbidden` responses.

### D. Verification & Automated Test Strategy
* **Unit/Integration Test:** Execute explicit `UPDATE` and `DELETE` queries against `audit_logs` using the test runner; assert that the database rejects the command with error code `55000`.
* **Tamper Verification:** Validate chain integrity by computing sequential hash validations across all rows.

---

## 3. Threat Vector 2: Path Traversal & Static Storage Exposure (TV-02)

### A. Threat Description & Threat Actor
An attacker attempts to upload files with malicious filenames containing directory traversal characters (e.g., `../../etc/passwd` or `..\..\Windows\System32\`), or attempts to access raw storage bucket URLs directly, bypassing authorization checks. Additionally, attackers may attempt to access files after permission revocation has occurred.

* **STRIDE Category:** Information Disclosure, Elevation of Privilege, Tampering.
* **OWASP API Classification:** API1: Broken Object Level Authorization (BOLA), API3: Broken Object Property Level Authorization.
* **Risk Severity:** **CRITICAL** (9.8/10 CVSS Vector).
* **Challenge Zero-Tolerance Rules:**
  * *Rule #2: Serving files from a static public folder (`express.static`) or exposing raw storage bucket URLs.*
  * *Rule #4: Inability to Revoke Access Instantly: Issuing long-lived tokens/URLs where revoked access remains functional.*

### B. Attack Scenarios
1. **Filename Path Traversal:** Attacker submits a multipart upload with a forged filename:
   ```http
   Content-Disposition: form-data; name="file"; filename="../../server/secrets/env.js"
   ```
2. **Static Bucket Direct Access:** Attacker extracts public Supabase or S3 storage bucket URLs from client bundles or API responses, accessing documents without server authorization:
   ```
   GET https://<project-ref>.supabase.co/storage/v1/object/public/documents/confidential.pdf
   ```
3. **Post-Revocation Access via Cached / Pre-signed URLs:** Attacker downloads an object using a pre-signed URL with a 1-hour expiry, 30 minutes after the document owner revoked their access grant.

### C. Defense-in-Depth Mitigation Strategy
1. **Zero Static File Serving (`express.static` Prohibited):**
   * The Express application contains no static directory mounts. All document access routes are protected by authorization middleware.
2. **Storage Path Virtualization & UUID Disassociation:**
   * Files stored in object storage are never named after user-supplied filenames.
   * File paths are generated server-side using secure UUIDs:
     `documents/{owner_id}/{uuidv4()}`.
   * Original filenames are sanitized (removing non-alphanumeric and path characters) and stored strictly as database metadata.
3. **Private Buckets & Server-Side Streaming Proxy:**
   * Storage buckets are marked private. Direct anonymous and public access is disabled.
   * The server streams file buffers to authorized clients through an Express route (`GET /api/documents/:id/download`) only after verifying live database permissions on every single request.
4. **Immediate Revocation Enforcement (0 Client-Trust):**
   * Pre-signed URLs are not issued to clients. Because each download goes through the API proxy with live database authorization checks, revoking a grant in `document_grants` immediately prevents subsequent byte streaming.

### D. Verification & Automated Test Strategy
* **Automated BOLA Test:** Verify that User B cannot download User A's document via direct ID reference without an active grant.
* **Path Traversal Test:** Attempt upload with `../../config/credentials.json`; assert sanitization strips traversal sequences and stores the file safely under UUID keys.
* **Immediate Revocation Test:** Grant READ permission to User B, verify download succeeds, revoke grant, immediately verify download returns `403 Forbidden`.

---

## 4. Day 2 Threat Model: Identity & Access Management

### TV-03: Weak Cryptographic Secrets & JWT Forgery
* **STRIDE Category:** Spoofing, Elevation of Privilege.
* **OWASP API Classification:** API2: Broken Authentication.
* **Attack Vector:** An attacker discovers or brute-forces an easily guessable default JWT signing secret (e.g. `'secret'` or `'changeit'`), signs forged tokens with arbitrary `role: 'ADMIN'` and user UUIDs, completely bypassing authentication checks.
* **Defense-in-Depth Mitigation:**
  1. `src/config/env.js` strictly blocks non-test startup if `JWT_SECRET` is unset.
  2. Issues security console warnings if secret length is under 32 characters.
  3. Tokens strictly verified using `jsonwebtoken` with HMAC-SHA256 signature verification.
* **Verification Strategy:** Automated unit tests attempt verifying tokens signed with malicious/different secrets, asserting `AuthTokenError` with code `TOKEN_INVALID`.

### TV-04: Credential Stuffing & Password Brute-Forcing
* **STRIDE Category:** Spoofing.
* **OWASP API Classification:** API2: Broken Authentication.
* **Attack Vector:** Threat actors utilize leaked credential dumps or automated dictionary scripts to guess passwords for high-privilege `ADMIN` or `OWNER` accounts.
* **Defense-in-Depth Mitigation:**
  1. Passwords hashed using `bcrypt` with minimum cost factor of 12 (`BCRYPT_SALT_ROUNDS=12`), enforcing high computational cost per hash evaluation.
  2. Minimum password length policy of 8+ characters enforced at trust boundary in controller and utility layer.
  3. Failed authentication attempts synchronously recorded to `audit_logs` (`LOGIN_FAILED_UNKNOWN_USER` and `LOGIN_FAILED_INVALID_PASSWORD`) with originating IP addresses for automated SIEM/alerting ingestion.
* **Verification Strategy:** Unit test asserts short passwords rejected; timing checks assert constant-time evaluation.

### TV-05: Account Enumeration Oracle via Error Analysis
* **STRIDE Category:** Information Disclosure.
* **OWASP API Classification:** API2: Broken Authentication.
* **Attack Vector:** Attackers submit login requests and analyze error messages (e.g. distinguishing between "User not found" and "Incorrect password") to build a list of registered employees.
* **Defense-in-Depth Mitigation:**
  1. Identical generic response string: `401 Unauthorized: { error: 'Invalid email or password.' }` returned for both unknown users and invalid passwords.
  2. Constant-time bcrypt comparison prevents response timing differentials from leaking whether a hash was computed.
* **Verification Strategy:** Route integration tests assert identical error messages across both failure modes.

### TV-06: Privilege Escalation via Unchecked Role Injection
* **STRIDE Category:** Elevation of Privilege.
* **OWASP API Classification:** API5: Broken Function Level Authorization.
* **Attack Vector:** A regular viewer submits `{ "role": "ADMIN" }` or arbitrary role strings during open registration, self-assigning full administrative access.
* **Defense-in-Depth Mitigation:**
  1. Input validation strictly whitelists roles against `['ADMIN', 'OWNER', 'VIEWER']`.
  2. Unspecified roles default safely to `'VIEWER'`.
  3. Registration events explicitly log `USER_REGISTERED` with the assigned role in `audit_logs`.
* **Verification Strategy:** Automated test verifies unauthorized roles return `400 Bad Request` and default registrations receive `VIEWER`.

---

## 5. Day 3 Threat Model: Document Access Control, Encryption & Storage Security

### Threat Matrix Update (Day 3)

| Threat ID | Threat Name | STRIDE Category | OWASP API | Severity | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TV-07** | Broken Object Level Authorization (BOLA) on Document Download | Elevation of Privilege, Info Disclosure | API1: Broken Object Level Auth (BOLA) | **CRITICAL** | **Mitigated (Three-Gate PEP Check + Audit Log)** |
| **TV-08** | AES-GCM Key/IV Misuse & Encryption Material Exposure | Tampering, Information Disclosure | API8: Security Misconfiguration | **CRITICAL** | **Mitigated (Atomic Envelope, Cryptographic Validation)** |
| **TV-09** | Malicious File Upload & Content-Type Injection | Tampering, Denial of Service, EoP | API4: Unrestricted Resource Consumption / API1: BOLA | **HIGH** | **Mitigated (MIME Validation, RAM Buffer, Size Limit)** |

---

### TV-07: Broken Object Level Authorization (BOLA) on Document Access
* **STRIDE Category:** Elevation of Privilege, Information Disclosure.
* **OWASP API Classification:** API1: Broken Object Level Authorization (BOLA) — the #1 ranked API security risk.
* **Attack Vector:** An authenticated viewer or unauthorized user directly supplies a known or enumerated document UUID to `GET /api/documents/:id/download`, bypassing any frontend-visible restriction checks and receiving another user's confidential encrypted document buffer.

#### Attack Scenario:
```http
GET /api/documents/e4a67b12-f2ab-4c11-ba23-987654321abc/download
Authorization: Bearer <viewer_jwt_without_any_grant>
```
→ Without server-side ownership/grant verification, the server returns the decrypted document.

#### Defense-in-Depth Mitigation:
1. **Three-Gate PEP Authorization Check (Live Database Evaluation):**
   * Every `downloadDocument` call executes a mandatory live authorization sequence:
     - Gate 1: `isOwner` — `req.user.id === document.owner_id`
     - Gate 2: `isAdmin` — `req.user.role === 'ADMIN'`
     - Gate 3: Active grant row in `document_grants` (`document_id + grantee_id` match)
   * All three gates are evaluated against live database state on every request, not against JWT claims alone.
2. **Immediate Revocation Enforcement:**
   * Revocation of a grant in `document_grants` immediately prevents byte streaming on the next request — no caching, no pre-signed URLs, no client-trust.
3. **Forensic Audit Trail for All Denied Attempts:**
   * Every failed authorization logs `UNAUTHORIZED_DOCUMENT_DOWNLOAD_ATTEMPT` with actor ID, document ID, IP address, and DENIED status to the append-only `audit_logs` table.
4. **BOLA Test Coverage:**
   * Automated integration test `"unauthorized user download attempt blocked with 403 Forbidden"` asserts a viewer without a grant receives exactly `403 Forbidden` with no document buffer in the response body.
* **Verification Strategy:** Integration tests assert BOLA resistance for `downloadDocument`, `listDocuments` (tenant isolation), and `deleteDocument` (owner/admin only).

---

### TV-08: AES-GCM Key/IV Misuse & Encryption Material Exposure
* **STRIDE Category:** Tampering, Information Disclosure.
* **OWASP API Classification:** API8: Security Misconfiguration (Cryptographic Failure).
* **Attack Vector:** An attacker targets weaknesses in the encryption implementation — static or predictable IVs, missing auth tag verification, or dissociated decryption material — to decrypt document buffers without the master key, or to forge ciphertext that passes authentication.

#### Attack Scenarios:
1. **IV Reuse Attack:** If a static or timestamp-derived IV is used with the same key, two ciphertexts XORed together reveal the plaintext of both documents (keystream reuse attack).
2. **Auth Tag Strip Attack:** An attacker modifies ciphertext in transit and omits/corrupts the GHASH authentication tag. If `decipher.setAuthTag()` is skipped, the tampered ciphertext decrypts silently.
3. **Envelope Dissociation Attack:** IV and auth tag stored in a separate database column are accidentally cleared by a migration or `UPDATE` query, leaving ciphertexts permanently unrecoverable.

#### Defense-in-Depth Mitigation:
1. **Fresh Cryptographically Secure 12-byte IV Per Encryption (`crypto.randomBytes(12)`):** Zero IV reuse probability; each document encryption is cryptographically independent.
2. **Mandatory GHASH Auth Tag Verification on Decryption:** `decipher.setAuthTag(Buffer.from(authTag, 'hex'))` is called before `decipher.final()`. Any tampering raises a `CryptoError: DECRYPTION_FAILED` and halts the pipeline.
3. **Atomic Composite Envelope (`storagePath#iv:authTag`):** IV and auth tag are stored atomically with the storage path in a single `storage_path` TEXT column. They cannot be dissociated by partial writes or column drops.
4. **64-Character Hex Master Key Enforcement:** `MASTER_ENCRYPTION_KEY` must be exactly 64 hex characters (32 bytes / 256-bit entropy). Startup fails fast if the key is missing, malformed, or shorter.
* **Verification Strategy:** Automated crypto tests assert IV uniqueness across repeated encryptions, auth tag tampering detection, and decryption rejection of corrupted ciphertexts.

---

### TV-09: Malicious File Upload & Content-Type Injection
* **STRIDE Category:** Tampering, Denial of Service, Elevation of Privilege.
* **OWASP API Classification:** API4: Unrestricted Resource Consumption, API1: Broken Object Level Authorization.
* **Attack Vector:** An attacker uploads maliciously crafted files — oversized payloads for OOM exhaustion, files with path traversal filenames, server-side script files disguised with spoofed MIME types, or polyglot files that execute as multiple content types.

#### Attack Scenarios:
1. **OOM Resource Exhaustion:** Attacker sends concurrent multipart uploads with 100MB+ payloads to exhaust server RAM and crash the Node.js process.
2. **Path Traversal via Filename Injection:**
   ```
   Content-Disposition: form-data; name="document"; filename="../../src/config/supabase.js"
   ```
3. **MIME Spoofing for Server-Side Execution:** Attacker uploads a `.js` or `.php` script with `Content-Type: application/pdf` to bypass content checks and achieve stored XSS or server-side execution.

#### Defense-in-Depth Mitigation:
1. **Strict 10MB RAM Buffer Limit (`multer.memoryStorage()`):** Hard `fileSize: 10 * 1024 * 1024` limit; single-file enforcement (`files: 1`). `LIMIT_FILE_SIZE` intercepted cleanly and returned as HTTP 400.
2. **Filename Sanitization & UUID-Based Storage Paths:** Original filenames stripped of all non-alphanumeric characters; storage paths use server-generated UUID keys. Attacker-controlled filenames never reach the filesystem or bucket.
3. **Private Bucket Enforcement — No Public URLs:** Storage bucket is configured as private. No direct browser-accessible URL exists for any stored object.
4. **In-Memory Encryption Before Any I/O:** Documents are AES-256-GCM encrypted in RAM before any write. Even if a script were uploaded, it would be stored as opaque ciphertext with no execution path.
* **Verification Strategy:** Upload tests assert 400 on oversized files; filename sanitization tests verify traversal sequences are stripped; auth middleware tests confirm unauthenticated uploads receive 401.
