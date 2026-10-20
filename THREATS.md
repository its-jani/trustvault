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
