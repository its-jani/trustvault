# TrustVault — Enterprise Secure Document Management Platform

TrustVault is an enterprise-grade, Zero-Trust secure document management and access delegation platform. Engineered with a defense-in-depth architectural model, TrustVault guarantees strict data confidentiality, cryptographic integrity, and compliance-ready auditability for sensitive digital assets.

Unlike conventional web systems that rely on perimeter defenses or client-side authorization, TrustVault treats every request as untrusted until verified by a server-side Policy Enforcement Point (PEP), encrypts all documents in memory before disk or cloud persistence, and enforces immutable audit logging directly at the database engine layer.

---

## Core Architectural Pillars

* **Zero-Trust Policy Enforcement Point (PEP):** Every document access, delegation, download, and deletion request is evaluated in real time against live database authorization rules. Client-side states and unvalidated JWT claims are strictly untrusted.
* **AES-256-GCM Envelope Encryption at Rest:** Files are encrypted in volatile memory prior to storage using AES-256-GCM with cryptographically random 96-bit initialization vectors (IV) and 128-bit authentication tags. Raw storage buckets never store plaintext data or public URLs.
* **Multi-Role RBAC & Fine-Grained Access Delegation:** Role-Based Access Control (`ADMIN`, `OWNER`, `VIEWER`) paired with fine-grained per-document delegation allows owners to grant granular view permissions to specific users.
* **Immediate Access Revocation:** Grant revocation takes effect instantaneously. Database-level policy checks block subsequent access with zero caching delay or token staleness.
* **Database-Enforced Immutable Audit Trail:** Security logs are recorded with SHA-256 tamper-evident integrity hashes. PostgreSQL PL/pgSQL database triggers intercept and block all `UPDATE` and `DELETE` operations at the engine level.

---

## Security Architecture & Implementation Highlights

### 1. Zero-Trust Access Pipeline
TrustVault enforces a strict three-gate Policy Enforcement Point (PEP) on every resource request:
1. **Perimeter Authentication Gate:** Validates the cryptographically signed HMAC-SHA256 Bearer JWT, checking signature validity, user identity existence, and token expiration.
2. **Role & Tenant Isolation Gate:** Verifies the user's role and scopes database queries so non-administrators can only view resources they own or have explicitly been delegated access to.
3. **Live Resource Permission Gate:** For document retrieval and decryption, queries the live `document_grants` table to ensure active authorization. If an access grant was revoked a millisecond earlier, access is immediately blocked with HTTP `403 Forbidden`.

### 2. Cryptographic Storage & In-Memory Streaming
* **In-Memory Encryption:** Uploaded document buffers are ingested strictly into RAM via Multer memory storage (capped at 10MB per file). Files never touch local server disks in unencrypted form.
* **AES-256-GCM Cipher:** Each file is encrypted with a unique, cryptographically secure 12-byte initialization vector (IV). An authentication tag is calculated to prevent ciphertext tampering.
* **Authenticated Streaming Proxy:** Document downloads stream encrypted ciphertext directly from private cloud object storage into application memory, decrypt the buffer using the master key and stored IV/tag, and stream plaintext bytes directly to the authorized client with strict `Content-Type` and `Content-Disposition` headers. Raw cloud storage bucket URLs are never exposed.

### 3. Database-Level Audit Immutability
All security-relevant actions (`USER_LOGIN_SUCCESS`, `DOCUMENT_UPLOADED`, `DOCUMENT_DOWNLOAD_SUCCESS`, `GRANT_CREATED`, `GRANT_REVOKED`, `UNAUTHORIZED_ACCESS_ATTEMPT`) are written to an append-only `audit_logs` table.

Immutability is guaranteed by a PostgreSQL PL/pgSQL trigger function:
```sql
CREATE OR REPLACE FUNCTION prevent_audit_log_alteration()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable. UPDATE and DELETE operations are forbidden.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_logs_immutability_trigger
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_alteration();
```
Any attempt by an application user, service, or administrative script to mutate or delete audit log records is aborted by the database engine.

### 4. Perimeter Defense & Input Sanitization
* **Rate Limiting:** Auth endpoints (`/api/auth/login`, `/api/auth/register`) are protected by IP-based rate limiting (10 attempts per 15 minutes) to mitigate credential stuffing and brute-force attacks. Global endpoints enforce a 200 request / 15-minute ceiling.
* **Recursive Input Sanitization:** Global middleware recursively sanitizes request bodies, query parameters, and route parameters, stripping malicious HTML tags, `<script>` injection vectors, `javascript:` pseudo-protocols, and null bytes (`\0`).
* **Security Headers:** Hardened HTTP response headers via `helmet` (HSTS, Frameguard, XSS protection, and restrictive Content Security Policy).

---

## Project Directory Structure

```text
trustvault/
├── .env.example              # Environment variable definitions template
├── .gitignore                 # Version control exclusions (secrets, builds, node_modules)
├── package.json               # Backend dependencies, scripts, and ES Module config
├── vercel.json                # Single-domain routing, serverless build & SPA fallback config
├── README.md                  # Enterprise platform documentation
├── THREATS.md                 # STRIDE threat model & attack vector register (TV-01 → TV-15)
├── PROMPTS.md                 # Architecture log, vulnerability analysis, and remediation records
├── client/                    # React 19 + Tailwind CSS + Vite frontend SPA
│   ├── src/
│   │   ├── api/               # Unified Axios API clients (auth, documents, grants, audit)
│   │   ├── components/        # UI components (DocumentVault, GrantModal, AuditLogViewer, etc.)
│   │   ├── contexts/          # Authentication & session state providers
│   │   ├── pages/             # Route views (LoginPage, RegisterPage, DashboardPage, AdminPage)
│   │   ├── App.jsx            # Application shell, navigation, and protected route wiring
│   │   ├── App.css            # Custom CSS animations and design tokens
│   │   └── main.jsx           # React DOM root entrypoint
│   ├── index.html             # Client HTML template
│   ├── package.json           # Frontend dependencies
│   └── vite.config.js         # Vite configuration with /api local proxy
├── tests/
│   ├── authUtils.test.js      # Password hashing & JWT cryptographic unit tests (10 tests)
│   ├── middleware.test.js     # PEP authentication & RBAC middleware tests (11 tests)
│   ├── authRoutes.test.js     # Auth API routes integration tests (12 tests)
│   ├── cryptoUtils.test.js    # AES-256-GCM encryption & tampering detection unit tests (9 tests)
│   ├── storageService.test.js # Multer ingestion & private storage service tests (6 tests)
│   ├── documentRoutes.test.js # Document API PEP access enforcement tests (13 tests)
│   ├── grantRoutes.test.js    # Grant delegation & instant revocation PEP tests (14 tests)
│   ├── auditRoutes.test.js    # Admin audit query, filtering & RBAC tests (11 tests)
│   └── rateLimiter.test.js    # Rate limiting, health check & sanitization tests (4 tests)
└── src/
    ├── config/
    │   ├── env.js             # Environment validation (JWT, AES, Supabase secrets)
    │   ├── schema.sql         # Supabase PostgreSQL DDL & immutability trigger definition
    │   └── supabase.js        # Headless Supabase client with Service Role authorization
    ├── controllers/
    │   ├── authController.js  # Registration, login, and identity controllers
    │   ├── documentController.js # Upload, download, list, delete controllers with PEP
    │   ├── grantController.js # Document access grant delegation and revocation handlers
    │   └── auditController.js # Admin forensic audit query and filter handlers
    ├── middleware/
    │   ├── auth.js            # PEP Bearer JWT authentication & audit logger
    │   ├── errorHandler.js    # Centralized Express error handler (no stack leaks in prod)
    │   ├── rateLimiter.js     # Perimeter defense & auth brute-force rate limiters (429)
    │   ├── rbac.js            # Policy Enforcement Point RBAC authorization
    │   ├── upload.js          # In-memory Multer middleware (RAM-only, 10MB limit)
    │   └── validator.js       # Global recursive HTML/script & null byte input sanitization
    ├── routes/
    │   ├── authRoutes.js      # Authentication route definitions
    │   ├── documentRoutes.js  # PEP-protected document route definitions
    │   ├── grantRoutes.js     # Grant delegation and revocation route definitions
    │   └── auditRoutes.js     # Admin-only forensic audit trail route definitions
    ├── services/
    │   ├── auditService.js    # Filtered and paginated forensic audit query service
    │   ├── grantService.js    # Document grant delegation, verification, and revocation service
    │   └── storageService.js  # Private Supabase Storage CRUD (upload/download/delete)
    ├── utils/
    │   ├── auditLogger.js     # Synchronous audit log persistence helper
    │   ├── crypto.js          # AES-256-GCM envelope encrypt/decrypt utilities
    │   ├── jwt.js             # Structured JWT issue & verify utilities
    │   └── password.js        # Constant-time bcrypt hashing utilities
    └── server.js              # Express app bootstrap, helmet, cors, and healthcheck route
```

---

## Setup & Deployment Runbook

### Prerequisites
* **Node.js**: v18.0.0 or higher
* **npm**: v9.0.0 or higher
* **PostgreSQL / Supabase**: Dedicated Supabase project with Storage Bucket configured

### Step 1: Install Dependencies
Install all backend and frontend packages:
```bash
# Install root backend dependencies
npm install

# Install client frontend dependencies
cd client && npm install && cd ..
```

### Step 2: Configure Environment Variables
Create a `.env` file in the project root based on `.env.example`:
```bash
cp .env.example .env
```

Set the required environment keys:
```env
# Server Configuration
PORT=5000
NODE_ENV=development

# Database & Storage (Supabase)
SUPABASE_URL=https://<your-project-id>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJh...<your-service-role-key>
SUPABASE_STORAGE_BUCKET=vault-documents

# Cryptographic Keys
JWT_SECRET=super-secure-32-character-secret-key-phrase
MASTER_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

> **Note on `MASTER_ENCRYPTION_KEY`:** Must be exactly a 64-character hexadecimal string representing a 256-bit (32-byte) symmetric key. Generate via:
> ```bash
> node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
> ```

### Step 3: Initialize Database Schema
1. Open your Supabase Project Dashboard and navigate to the **SQL Editor**.
2. Paste and run the contents of [`src/config/schema.sql`](./src/config/schema.sql).
3. The script will create:
   * Tables: `users`, `documents`, `document_grants`, `audit_logs`
   * Role enum: `user_role` (`ADMIN`, `OWNER`, `VIEWER`)
   * Permission enum: `grant_permission` (`READ`, `EDIT`)
   * Database triggers: `prevent_audit_log_alteration` (enforcing audit immutability)
4. Ensure the private bucket named `vault-documents` exists under Supabase **Storage** (Public access disabled).

### Step 4: Run the Application Locally

#### Backend Development Server (Port 5000)
```bash
npm run dev
```

#### Frontend Development Server (Port 5173)
```bash
cd client
npm run dev
```
The React frontend dev server automatically proxies `/api` calls to `http://localhost:5000`.

#### Production Mode
```bash
npm start
```

---

## Production Deployment on Vercel

TrustVault is pre-configured for single-domain deployment on Vercel via [`vercel.json`](./vercel.json).

### 1. Unified Single-Domain Routing
* **Serverless Backend:** `src/server.js` is bundled via `@vercel/node`.
* **Frontend SPA:** `client/` is compiled via `@vercel/vite`.
* **Routing Rules:**
  * `/api/(.*)` &rarr; Routed directly to the Express serverless function (`src/server.js`).
  * `/health` &rarr; Routed directly to `src/server.js` (public liveness probe).
  * `/(.*)` &rarr; Routed to the client single-page application with HTML5 pushState fallback (`/client/index.html`).

### 2. Vercel Environment Variables
Add the following keys in your **Vercel Project Settings &rarr; Environment Variables**:
* `SUPABASE_URL`
* `SUPABASE_SERVICE_ROLE_KEY`
* `SUPABASE_STORAGE_BUCKET`
* `JWT_SECRET`
* `MASTER_ENCRYPTION_KEY`
* `NODE_ENV=production`

---

## Automated Testing Suite

TrustVault includes a comprehensive automated test harness covering cryptographic security, PEP enforcement, tenant isolation, and audit log validation.

```bash
npm test
```

### Test Coverage Summary (90 Tests Across 9 Suites — 100% Passing):
| Test Suite | Tests | Validation Scope |
|---|:---:|---|
| `authUtils.test.js` | 10 | bcrypt salt rounds, constant-time verification, JWT signing, signature tampering rejection |
| `middleware.test.js` | 11 | PEP Bearer token extraction, invalid token denial, RBAC policy enforcement, audit log generation |
| `authRoutes.test.js` | 12 | User registration, login verification, current identity query, duplicate account protection |
| `cryptoUtils.test.js` | 9 | AES-256-GCM encryption/decryption, 96-bit IV uniqueness, auth tag tampering detection |
| `storageService.test.js` | 6 | Multer 10MB file limit enforcement, volatile RAM buffer handling, private storage CRUD |
| `documentRoutes.test.js` | 13 | BOLA prevention, tenant isolation, PEP-protected encrypted upload, streaming download, delete |
| `grantRoutes.test.js` | 14 | Access delegation, live revocation enforcement, self-granting rejection, unauthorized grant access |
| `auditRoutes.test.js` | 11 | Admin-only RBAC, limit clamping (max 100), action/actor/date filtering, malformed input handling |
| `rateLimiter.test.js` | 4 | Public `/health` liveness probe, recursive HTML/script sanitization, 429 rate limit enforcement |

---

## REST API Reference

All protected endpoints require an `Authorization: Bearer <token>` header.

### 1. System Health
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/health` | Public | System liveness probe returning uptime, timestamp, and health status |

### 2. Authentication API (`/api/auth`)
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | Public | Register new user identity (`ADMIN`, `OWNER`, `VIEWER`). Returns sanitized user object |
| `POST` | `/api/auth/login` | Public | Authenticate credentials. Returns signed HMAC-SHA256 JWT and user profile |
| `GET` | `/api/auth/me` | Protected | Returns authenticated user profile resolved from verified Bearer token |

### 3. Document Management API (`/api/documents`)
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/documents/upload` | Protected | Multipart upload (`document` file, `title`, `category`). Encrypted in RAM before storage |
| `GET` | `/api/documents` | Protected | List documents. Enforces tenant isolation (owners see own; delegates see granted; admins see all) |
| `GET` | `/api/documents/:id/download` | Protected | Live PEP-authorized download. Ciphertext decrypted in memory and streamed directly |
| `DELETE` | `/api/documents/:id` | Protected | Delete document. Restricted to document owner or system administrator |
| `GET` | `/api/documents/:id/permissions` | Protected | List active access grants for a document with grantee and granter identities |

### 4. Access Delegation API (`/api/grants`)
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/grants` | Protected | Grant access permission (`READ`, `EDIT`) to a grantee by email. Self-granting blocked |
| `GET` | `/api/grants/document/:documentId` | Protected | Retrieve all active delegation grants for a specific document (Owner / Admin only) |
| `DELETE` | `/api/grants/:id` | Protected | Immediately revoke access grant. Revocation takes effect with zero caching latency |

### 5. Forensic Audit Trail API (`/api/audit-logs`)
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/api/audit-logs` | Admin Only | Query immutable security audit logs with pagination and filters (`action`, `actorId`, `date`) |

---

## Security Governance & Compliance Documentation

* **STRIDE Threat Modeling ([`THREATS.md`](./THREATS.md)):** Comprehensive threat register detailing 15 attack vectors (TV-01 through TV-15) covering BOLA, audit immutability, cryptographic misuse, rate limiting, and input sanitization alongside technical mitigations and automated test references.
* **Architecture & Governance Log ([`PROMPTS.md`](./PROMPTS.md)):** Engineering audit log recording architectural decisions, vulnerability remediations, and design evolution across the platform lifecycle.
