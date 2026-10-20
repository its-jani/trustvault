# TrustVault — AI Interaction & Prompt Engineering Audit Log (`PROMPTS.md`)

This log provides an honest, auditable record of all AI interactions throughout the development of TrustVault for the Snovasys Hiring Challenge 2026. Every entry documents the original prompt, the AI-generated output, security vulnerabilities or architectural flaws detected in that output, and the corrective engineering measures implemented.

---

## Entry 1: Initial Database Schema Design & Audit Immutability Enforcement
* **Date:** 2026-10-19
* **Developer/Engineer:** Lead Security Software Engineer
* **Phase:** Day 1 — Foundation & Schema Architecture
* **Component:** Database Schema (Supabase / PostgreSQL)

### 1. Context & User Prompt
The initial objective was to define a production-grade relational database schema for TrustVault supporting user identities, role-based controls, document metadata, explicit document grants, and an audit trail.

**Prompt Submitted:**
> *"Generate a PostgreSQL schema for a security-first document management platform called TrustVault. The schema needs to support users (roles: ADMIN, OWNER, VIEWER), documents (metadata and owner), explicit permissions (grants for READ/EDIT), and an audit log table that records all access attempts and modifications."*

---

### 2. AI-Generated Output (Summary & Flaws)
The AI produced standard DDL statements:
* Created `users`, `documents`, `document_grants`, and an `audit_logs` table.
* Used basic primary and foreign keys.
* Created standard B-Tree indexes on foreign keys.

```sql
-- AI-Generated Snippet (Exemplary excerpt showing flaws)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    actor_id UUID REFERENCES users(id),
    action VARCHAR(50),
    document_id UUID REFERENCES documents(id),
    details JSONB
);
```

---

### 3. Critical Security Flaws Identified by Engineer

1. **Absence of Audit Log Immutability (Zero-Tolerance Violation):**
   * **Flaw:** The AI created a mutable SQL table. Any process, service role script, or compromised SQL query could execute `UPDATE audit_logs SET ...` or `DELETE FROM audit_logs WHERE ...` without restriction.
   * **Impact:** High severity. An adversary or rogue administrator could alter audit history to cover unauthorized document exfiltration or access denial incidents.
   * **Rule Violated:** Zero-Tolerance Rule #3: *Audit Log Tampering: Allowing UPDATE or DELETE SQL queries against audit_logs.*

2. **Lack of Cryptographic Hash Chaining Fields:**
   * **Flaw:** The AI did not incorporate fields for tamper-evident chaining (`previous_hash`, `current_hash`).
   * **Impact:** Without a cryptographic integrity trail, database snapshots cannot be mathematically verified against external verification anchors.

3. **Inadequate Cascade vs. Restrict Semantics on Forensic Logs:**
   * **Flaw:** If a user or document was deleted, standard `ON DELETE CASCADE` on `audit_logs` would purge historical forensic records associated with that entity.
   * **Resolution:** Audit log foreign keys must use `ON DELETE SET NULL` or remain unconstrained IDs to prevent cascade deletion of historical records.

---

### 4. Human Remediation & Corrective Implementation

To satisfy the zero-tolerance security requirements, a custom PostgreSQL PL/pgSQL trigger function `prevent_audit_log_alteration()` was engineered. This trigger intercepts any `UPDATE` or `DELETE` attempt at the database engine level and terminates the transaction with an explicit security exception.

Additionally, `previous_hash` and `current_hash` columns were added to support cryptographic verification chains.

#### Production Schema & Trigger Script (Executed via Supabase Dashboard):

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Define Custom Enum Types
CREATE TYPE user_role AS ENUM ('ADMIN', 'OWNER', 'VIEWER');
CREATE TYPE grant_permission AS ENUM ('READ', 'EDIT');

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'VIEWER',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Documents Table
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL DEFAULT 'General',
    storage_path TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Document Grants Table (Explicit Per-User Permissions)
CREATE TABLE IF NOT EXISTS document_grants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    grantee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission grant_permission NOT NULL,
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_document_grantee UNIQUE (document_id, grantee_id)
);

-- 4. Audit Logs Table (Append-Only, Tamper-Evident)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    document_id UUID REFERENCES documents(id) ON DELETE SET NULL,
    details JSONB DEFAULT '{}'::jsonb,
    previous_hash VARCHAR(64),
    current_hash VARCHAR(64)
);

-- Indexes for fast query performance & search
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
CREATE INDEX IF NOT EXISTS idx_grants_lookup ON document_grants(document_id, grantee_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_document ON audit_logs(document_id);

-- 5. Immutability Enforcement Trigger for Audit Logs
CREATE OR REPLACE FUNCTION prevent_audit_log_alteration()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'TRUSTVAULT_SECURITY_VIOLATION: The audit_logs table is append-only. Modification (UPDATE) or deletion (DELETE) is strictly prohibited by security policy.'
        USING ERRCODE = '55000'; -- Object not in prerequisite state / custom violation
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_audit_log_alteration ON audit_logs;

CREATE TRIGGER trg_prevent_audit_log_alteration
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_alteration();
```

---

### 5. Architectural Verification & Conclusion
* **Result:** Running `UPDATE audit_logs ...` or `DELETE FROM audit_logs ...` immediately fails with SQLSTATE `55000` and error message `TRUSTVAULT_SECURITY_VIOLATION`.
* **Takeaway:** AI provides a functional baseline for standard database schemas, but lacks adversarial security instincts. Without manual human intervention to enforce database-level triggers, audit trails remain vulnerable to tampering.

---

## Entry 2: Cryptographic Utilities & JWT Role Token Architecture
* **Date:** 2026-10-20
* **Developer/Engineer:** Lead Security Software Engineer
* **Phase:** Day 2 — Phase 2.1: Cryptographic Utilities & JWT Token Manager
* **Component:** `src/utils/password.js`, `src/utils/jwt.js`, `src/config/env.js`

### 1. Context & User Prompt
Implement cryptographic hashing (`bcryptjs`) and JWT token issuing/verifying utilities supporting `ADMIN`, `OWNER`, and `VIEWER` roles with strict environment checks.

### 2. Common AI Security Flaws Caught & Mitigated
1. **Unvalidated Claims in JWT Payload:**
   * *Flaw:* AI often accepts any arbitrary object as payload, allowing caller injection or forged roles (e.g. `{ role: 'SUPERADMIN' }`).
   * *Remediation:* Enforced strict claim verification in `generateToken`: `id`, `email`, and explicit validation against `VALID_ROLES` (`ADMIN`, `OWNER`, `VIEWER`).
2. **Ambiguous Error Obfuscation:**
   * *Flaw:* Generic `try/catch` blocks in AI-generated JWT modules often mask expiration as general invalidity or leak raw stack traces to callers.
   * *Remediation:* Created structured `AuthTokenError` with discrete error codes (`TOKEN_EXPIRED`, `TOKEN_INVALID`, `TOKEN_MISSING`) and HTTP status 401.
3. **Environment Misconfiguration Vulnerabilities:**
   * *Flaw:* Using default fallback secrets in production environments.
   * *Remediation:* `src/config/env.js` enforces a fatal throw if `JWT_SECRET` is unset in non-test runtime environments and issues security warnings if secret length is under 32 characters.

---

## Entry 3: Policy Enforcement Point (PEP) & RBAC Authorization Middleware
* **Date:** 2026-10-20
* **Developer/Engineer:** Lead Security Software Engineer
* **Phase:** Day 2 — Phase 2.2: PEP Authentication & RBAC Middleware with Audit Logging
* **Component:** `src/utils/auditLogger.js`, `src/middleware/auth.js`, `src/middleware/rbac.js`

### 1. Context & User Prompt
Implement Policy Enforcement Point (PEP) middleware layers that intercept incoming HTTP requests, verify JWT signatures, enforce Role-Based Access Control (RBAC) across `ADMIN`, `OWNER`, and `VIEWER`, and synchronously record both unauthorized and forbidden access attempts into `audit_logs`.

### 2. Common AI Security Flaws Caught & Mitigated
1. **Unlogged Access Denials & Blind Rejections:**
   * *Flaw:* Standard AI-generated middleware emits immediate `401` or `403` responses without forensic records. This leaves security administrators blind to brute-force token enumeration, token replay, or privilege escalation probes.
   * *Remediation:* Every denial path (`UNAUTHORIZED_ACCESS_ATTEMPT`, `INVALID_TOKEN_ATTEMPT`, `FORBIDDEN_ROLE_ATTEMPT`) synchronously invokes `logAuditEvent()` before returning the response, capturing actor, IP, timestamp, and attempted roles.
2. **Audit Failure Cascading to Pipeline Crash:**
   * *Flaw:* AI often awaits database writes without error boundary containment. If the audit database experiences transient downtime or foreign key mismatches on untrusted actor UUIDs, an unhandled rejection crashes the API request pipeline.
   * *Remediation:* `logAuditEvent()` wraps all persistence operations in safe boundaries, sanitizes UUIDs, and logs failures to `console.error` without halting the core request/response lifecycle.
3. **Insecure Role Normalization & Type Confusion:**
   * *Flaw:* AI frequently evaluates role checks via loose string equality or fails to assert the presence of `req.user`, causing unexpected `TypeError: Cannot read properties of undefined (reading 'role')` when unauthenticated users hit role-gated routes.
   * *Remediation:* `requireRole()` normalizes single and multiple role parameters into strict arrays, safely evaluates `req.user`, and defaults unauthenticated actors to `'ANONYMOUS'` in forensic audit logs.


