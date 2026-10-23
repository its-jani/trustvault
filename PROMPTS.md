# TrustVault — AI Interaction & Security Engineering Audit Log (`PROMPTS.md`)

This log provides a transparent, auditable record of how AI assistance was utilized, scrutinized, and corrected across each phase of building TrustVault for the Snovasys Hiring Challenge 2026. Every section documents the phase objective, key architectural decisions, and the critical security flaws identified and mitigated by the engineering team.

---

## Day 1: Foundation, Hardened Core & Schema Immutability

### 1. Objective
Establish the production PostgreSQL database schema, Express application core, defense-in-depth HTTP security headers, startup fail-fast environment validation, and centralized operational error handling.

### 2. Key Architectural Decisions
* **Database Schema (`src/config/schema.sql`):** Designed normalized tables for `users`, `documents`, `document_grants`, and `audit_logs` with custom PostgreSQL ENUMs (`user_role`, `grant_permission`) and performance indexes.
* **HTTP Security Hardening (`src/server.js`):** Implemented Helmet with strict Content Security Policy (CSP), HTTP Strict Transport Security (HSTS preloading), frameguard clickjacking protection, and origin-validated CORS whitelisting.
* **Centralized Error Handling (`src/middleware/errorHandler.js`):** Created an `AppError` operational error class. Non-operational errors and raw stack traces are strictly suppressed in production responses to prevent internal reconnaissance.
* **Fail-Fast Environment Validation (`src/config/env.js`):** Enforced synchronous validation of mandatory environment variables on process startup.

### 3. Security Flaws Caught & Mitigated
* **Mutable Audit Logs (Zero-Tolerance Violation):** AI generated standard mutable SQL tables where `UPDATE` or `DELETE` could erase access trails. Engineered a database-level PL/pgSQL trigger (`prevent_audit_log_alteration`) that terminates any tampering attempt with a PostgreSQL exception.
* **Information Leakage via Error Responses:** AI error handlers returned unhandled database error objects and raw stack traces directly to API clients. Replaced with standardized JSON error envelopes.
* **Permissive CORS Wildcarding:** AI boilerplate defaulted to `origin: '*'` alongside credentials. Replaced with explicit origin validation against allowed frontend domains.

---

## Day 2: Authentication, Password Cryptography & PEP Enforcement

### 1. Objective
Build server-side user authentication, industry-standard password hashing, stateless JWT session tokens, and Policy Enforcement Point (PEP) middleware with synchronous forensic audit logging.

### 2. Key Architectural Decisions
* **Password Hashing (`src/utils/password.js`):** Implemented `bcryptjs` with cost factor 12 (4,096 rounds), providing brute-force resistance without blocking the Node event loop.
* **Stateless JWT Session Management (`src/utils/jwt.js`):** Configured signed HMAC-SHA256 tokens with a 1-hour expiration window, pinned algorithms, and UUID-based identity payload claims.
* **PEP Middleware Layer (`src/middleware/auth.js`, `src/middleware/rbac.js`):** Intercepts incoming requests, validates Bearer JWT signatures, enforces role permissions (`ADMIN`, `OWNER`, `VIEWER`), and attaches verified claims to `req.user`.
* **Synchronous Audit Logging (`src/utils/auditLogger.js`):** Synchronously records authentication successes and denials to `audit_logs` using a service-role Supabase client.

### 3. Security Flaws Caught & Mitigated
* **JWT Algorithm Confusion Bypass:** AI verification omitted the `algorithms: ['HS256']` constraint, leaving endpoints vulnerable to `none` algorithm forging. Enforced strict cryptographic algorithm pinning.
* **Weak Hashing Defaults:** AI generated sample code with low salt rounds (10). Upgraded to cost factor 12 with mandatory 8-character minimum password validation.
* **Account Enumeration via Auth Discrepancies:** AI login handlers returned distinct messages (`"User not found"` vs `"Incorrect password"`). Unified into an identical generic response: `"Invalid email or password."`.
* **Pipeline Crashes on Audit Failures:** AI audit implementations let unhandled database insert rejections crash the request pipeline. Wrapped audit writes in fail-safe blocks that preserve core request execution while alerting stderr.

---

## Day 3: AES-256-GCM Envelope Encryption & Document Storage

### 1. Objective
Build in-memory authenticated envelope encryption (AES-256-GCM), RAM-only file ingestion, secure private cloud storage integration, and tenant-isolated document management endpoints.

### 2. Key Architectural Decisions
* **Envelope Encryption (`src/utils/crypto.js`):** Encrypts document buffers in RAM using AES-256-GCM with fresh 12-byte Initialization Vectors (IVs) and 128-bit authentication tags per operation.
* **Atomic Storage Reference Coupling:** Persists ciphertext references as composite strings (`storagePath#iv:authTag`), guaranteeing that IVs and authentication tags travel atomically with file pointers.
* **RAM-Only Ingestion (`src/middleware/upload.js`):** Configured `multer.memoryStorage()` with a hard 10MB ceiling; unencrypted plaintext buffers are never written to physical disk.
* **Private Cloud Storage Integration (`src/services/storageService.js`):** Interfaces with private Supabase Storage buckets enforcing `upsert: false` to prevent ciphertext overwriting.
* **Three-Gate Policy Enforcement (`src/controllers/documentController.js`):** Enforces access verification on every download: Gate 1 (`isOwner`), Gate 2 (`isAdmin`), or Gate 3 (active grant in `document_grants`).

### 3. Security Flaws Caught & Mitigated
* **Plaintext Spilling to Disk (Zero-Tolerance Violation):** AI upload boilerplates defaulted to `multer.diskStorage()` or temporary directories (`/tmp`). Replaced with RAM-only streaming buffers.
* **Broken Object Level Authorization (BOLA):** AI download handlers served files by ID without ownership verification. Implemented the three-gate PEP check and logged unauthorized download attempts.
* **Tenant Isolation Breaches in Listing:** AI list handlers accepted client-provided owner filters. Enforced server-side query scoping using `req.user.id` so non-admin users only receive owned or explicitly granted documents.
* **Orphaned Storage Blobs:** AI code omitted transactional cleanup when database inserts failed after storage upload. Added automated rollback that deletes storage objects if metadata insertion fails.

---

## Day 4: Grant Delegation Subsystem & Admin Forensic Inspection

### 1. Objective
Implement fine-grained document access delegation, immediate grant revocation without token latency, and an administrative security audit query endpoint.

### 2. Key Architectural Decisions
* **Grant Delegation Service (`src/services/grantService.js`):** Enables document owners and administrators to delegate view permissions to registered users by email or user ID (`POST /api/grants`).
* **Immediate Revocation Enforcement:** Deleting a grant (`DELETE /api/grants/:id`) immediately invalidates subsequent downloads at the PEP gate without waiting for token expirations or cached permissions.
* **Administrative Audit Inspection (`src/services/auditService.js`, `/api/audit-logs`):** Enables admins to query, filter (by action, actorId, documentId, date bounds), and page through immutable audit logs with DoS-resistant limit clamping (max 100).
* **Double-Layered Defense-in-Depth:** Route-level `requireRole(['ADMIN'])` paired with service-level caller role verification prevents unauthorized inspection attempts even if routing middleware is bypassed.

### 3. Security Flaws Caught & Mitigated
* **Privilege Escalation on Grant Delegation:** AI implementations accepted `documentId` without verifying that the caller owned the document or held admin rights. Enforced server-side ownership checks returning `403 Forbidden`.
* **Self-Granting Invariant Violation:** AI code allowed users to grant documents to themselves. Implemented explicit validation rejecting self-delegation with `400 Bad Request`.
* **Unauthorized Grant Revocation:** AI DELETE handlers allowed any authenticated user to revoke any grant by ID. Restricted revocation authority strictly to document owners, grant creators, or admins.
* **Database Schema Column Hallucinations:** AI code assumed standard Prisma/Rails conventions (`created_at`, `granted_to`). Reconciled against PostgreSQL schema constraints (`timestamp`, `grantee_id`), mapped clean API aliases, and validated UUID inputs against RFC 4122.

---

## Day 5: Final Backend Hardening, Rate Limiting & Input Sanitization

### 1. Objective
Implement perimeter rate limiting to neutralize brute-force/credential-stuffing attacks, add recursive input sanitization, expose a public health check probe, and configure cross-origin security headers for frontend integration.

### 2. Key Architectural Decisions
* **Perimeter Rate Limiting (`src/middleware/rateLimiter.js`):** Applied `express-rate-limit` to sensitive auth routes (`/api/auth/login`, `/api/auth/register`) with a 10 req / 15-minute cap (HTTP `429 Too Many Requests`), alongside a global 200 req / 15-minute cap across `/api/*`.
* **Recursive Input Sanitization (`src/middleware/validator.js`):** Recursively inspects and cleans `req.body`, `req.query`, and `req.params`, stripping null bytes, script tags, HTML elements, and `javascript:` pseudo-protocols.
* **Public Health Probe (`GET /health`):** Lightweight liveness probe reporting `{ status: 'healthy', timestamp, uptime }` without requiring authentication.
* **Cross-Origin Security Hardening (`src/server.js`):** Adjusted Helmet policies (`crossOriginResourcePolicy: 'cross-origin'`, `crossOriginEmbedderPolicy: false`) enabling seamless, secure SPA frontend integration.

### 3. Security Flaws Caught & Mitigated
* **Authentication Brute-Force & Bcrypt CPU Starvation:** AI endpoints lacked rate limiting, allowing attackers to submit uncontrolled login requests to exhaust server CPU on cost-factor 12 hashing. Throttled auth endpoints with 429 status enforcement.
* **Test Isolation Degradation:** Naive rate limiters apply global in-memory counters that throttle integration test suites running rapid registration cycles. Engineered test-aware bypass triggers (`x-test-rate-limit`) preserving strict production enforcement without test interference.
* **Stored XSS & Null Byte Truncation:** AI controllers assumed incoming JSON strings were clean. Added recursive sanitization to strip script blocks and null bytes before downstream database ingestion.
