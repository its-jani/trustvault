# TrustVault — Security-First Document Platform

**Snovasys Hiring Challenge 2026**  
**Lead Security Software Engineer: Project Implementation**

---

## 1. Project Overview & Philosophy

**TrustVault** is a document-sharing platform engineered under a strict **Zero-Trust** security architecture. Unlike conventional web applications that prioritize superficial UI screens, TrustVault places unbreachable server-side authorization, immutable audit logging, and immediate access revocation at the core of every architectural decision.

### Key Evaluation Focus Areas:
* **Security & Authorization (35%):** Live server-side Policy Enforcement Point (PEP) checks on every request. Zero trust in client state or unvalidated JWTs.
* **Threat Thinking (15%):** Continuous STRIDE threat modeling in [`THREATS.md`](./THREATS.md) and automated isolation test coverage.
* **Core Functionality (15%):** Complete multi-role document lifecycle with explicit per-document grants.
* **AI Governance & Auditability (15%):** Comprehensive [`PROMPTS.md`](./PROMPTS.md) documenting AI generation, flaw detection, and engineer-driven remediation.
* **Engineering Quality (10%):** Robust Express ES Modules structure, centralized error handling, and strict environment configuration.
* **Documentation & Deployment (10%):** Step-by-step reproducibility and cloud-ready deployment architecture.

### Zero-Tolerance Rules:
1. **Client-Side Authorization:** Never rely on UI button hiding or unvalidated JWT payloads. Every access request is verified against the database.
2. **Insecure File Storage:** No files served via `express.static`. Raw storage bucket URLs are strictly hidden behind authenticated streaming proxies.
3. **Audit Log Tampering:** `UPDATE` and `DELETE` SQL operations on `audit_logs` are blocked by a PostgreSQL engine trigger.
4. **Immediate Revocation:** Revoking permissions in `document_grants` immediately invalidates subsequent download/view requests without cached token latency.
5. **Mandatory Documentation:** AI logs (`PROMPTS.md`) and threat registers (`THREATS.md`) maintained throughout development.

---

## 2. Technology Stack

* **Runtime:** Node.js (>= 18.0.0)
* **Backend Framework:** Express.js (ES Modules: `import` / `export`)
* **Database:** PostgreSQL on Supabase Cloud
* **Database Client:** `@supabase/supabase-js` (Configured with Service Role Key for PEP execution, session persistence disabled)
* **Security Middleware:** `helmet` (HSTS, CSP, Frameguard, XSS protection), `cors` (origin allowlisting)
* **Process Management:** `nodemon` (Development), Native Node (Production)

---

## 3. Project Directory Structure

```text
trustvault/
├── .env.example              # Environment variables template
├── .gitignore                 # Secrets, logs, and dependency ignore rules
├── package.json               # Dependencies and scripts (ES Modules)
├── vercel.json                # Vercel single-domain routing & build configuration
├── README.md                  # Project overview and runbook
├── PROMPTS.md                 # AI prompt log, vulnerability analysis, and fixes (Days 1–6)
├── THREATS.md                 # STRIDE threat model & attack vector register (TV-01 → TV-15)
├── client/                    # React 19 + Tailwind v4 + Vite frontend SPA
│   ├── src/                   # Components, API clients, contexts, pages
│   └── package.json           # Frontend dependencies
├── tests/
│   ├── authUtils.test.js      # Password & JWT cryptographic unit tests (10 tests)
│   ├── middleware.test.js     # PEP authentication & RBAC middleware tests (11 tests)
│   ├── authRoutes.test.js     # Auth API routes integration tests (12 tests)
│   ├── cryptoUtils.test.js    # AES-256-GCM crypto utilities unit tests (9 tests)
│   ├── storageService.test.js # Multer ingestion & storage service tests (6 tests)
│   ├── documentRoutes.test.js # Document API PEP access enforcement tests (13 tests)
│   ├── grantRoutes.test.js    # Grant delegation & immediate revocation PEP tests (14 tests)
│   ├── auditRoutes.test.js    # Admin audit query, filtering & RBAC tests (11 tests)
│   └── rateLimiter.test.js    # Rate limiting, health check & sanitization tests (4 tests)
└── src/
    ├── config/
    │   ├── env.js             # Validated environment configurations (JWT, AES, Supabase)
    │   ├── schema.sql         # Supabase PostgreSQL schema DDL with immutability trigger
    │   └── supabase.js        # Headless Supabase client with Service Role authorization
    ├── controllers/
    │   ├── authController.js  # Registration, login, and identity controllers
    │   ├── documentController.js # Upload, download, list, delete controllers with PEP
    │   ├── grantController.js # Document access grant delegation and revocation handlers
    │   └── auditController.js # Admin forensic audit query and filter handlers
    ├── middleware/
    │   ├── auth.js            # PEP Bearer JWT authentication & audit logger
    │   ├── errorHandler.js    # Centralized Express error handler (no stack leaks in prod)
    │   ├── rbac.js            # Policy Enforcement Point RBAC authorization
    │   ├── upload.js          # In-memory Multer middleware (RAM-only, 10MB limit)
    │   ├── rateLimiter.js     # Perimeter defense & auth brute-force rate limiters (429)
    │   └── validator.js       # Global recursive HTML/script & null byte input sanitization
    ├── routes/
    │   ├── authRoutes.js      # Public/protected auth route definitions
    │   ├── documentRoutes.js  # PEP-protected document route definitions
    │   ├── grantRoutes.js     # Grant delegation and revocation route definitions
    │   └── auditRoutes.js     # Admin-only forensic audit trail route definitions
    ├── services/
    │   ├── storageService.js  # Private Supabase Storage CRUD (upload/download/delete)
    │   ├── grantService.js    # Document grant delegation, verification, and revocation service
    │   └── auditService.js    # Filtered and paginated forensic audit query service
    ├── utils/
    │   ├── auditLogger.js     # Synchronous audit log persistence helper
    │   ├── crypto.js          # AES-256-GCM envelope encrypt/decrypt utilities
    │   ├── jwt.js             # Structured JWT issue & verify utilities
    │   └── password.js        # Constant-time bcrypt hashing utilities
    └── server.js              # Express app bootstrap, helmet, cors, and healthcheck route
```

---

## 4. Getting Started & Local Execution

### Prerequisites:
* **Node.js** (v18.0.0 or higher recommended)
* **npm** (v9.0.0 or higher)
* A **Supabase** account and project (for PostgreSQL database access)

### Step 1: Install Dependencies
```bash
npm install
```

### Step 2: Configure Environment Variables
Copy the `.env.example` file to `.env`:
```bash
cp .env.example .env
```
Populate `.env` with your Supabase credentials and desired port:
```env
PORT=5000
NODE_ENV=development
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJh...your-service-role-key-here
```

### Step 3: Initialize Database Schema on Supabase
1. Navigate to your Supabase project dashboard at [supabase.com](https://supabase.com).
2. Open the **SQL Editor** from the left navigation panel.
3. Copy the contents of [`src/config/schema.sql`](./src/config/schema.sql) and paste them into the SQL editor.
4. Click **Run** to execute the migration. This creates:
   * `users` table with `user_role` ENUM (`ADMIN`, `OWNER`, `VIEWER`).
   * `documents` table with owner foreign key.
   * `document_grants` table with composite unique constraint.
   * `audit_logs` table with `previous_hash` and `current_hash` integrity columns.
   * `prevent_audit_log_alteration` PL/pgSQL trigger enforcing immutability.

### Step 4: Run the Application

#### Development Mode (with automatic reload via nodemon):
```bash
npm run dev
```

#### Production Mode:
```bash
npm start
```

---

## 5. API Verification & Healthcheck

Once the server is running, verify the health status by sending a `GET` request:

```bash
curl http://localhost:5000/api/health
```

### Expected Response:
```json
{
  "status": "healthy",
  "timestamp": "2026-10-19T12:00:00.000Z",
  "environment": "development",
  "database": {
    "status": "connected"
  },
  "uptimeSeconds": 12
}
```

---

## 6. Authentication API Endpoints

### 1. Register User
* **Endpoint:** `POST /api/auth/register`
* **Access:** Public
* **Request Body:**
  ```json
  {
    "email": "engineer@trustvault.local",
    "password": "Password123!Secure",
    "full_name": "Lead Security Engineer",
    "role": "OWNER"
  }
  ```
  *(Roles permitted: `ADMIN`, `OWNER`, `VIEWER`. Defaults to `VIEWER`.)*
* **Response (`201 Created`):**
  ```json
  {
    "message": "User registered successfully.",
    "user": {
      "id": "e6a2bc34-45a7-4c12-98ab-8c9012345678",
      "email": "engineer@trustvault.local",
      "full_name": "Lead Security Engineer",
      "role": "OWNER",
      "created_at": "2026-10-20T12:00:00.000Z"
    }
  }
  ```

### 2. User Login
* **Endpoint:** `POST /api/auth/login`
* **Access:** Public
* **Request Body:**
  ```json
  {
    "email": "engineer@trustvault.local",
    "password": "Password123!Secure"
  }
  ```
* **Response (`200 OK`):**
  ```json
  {
    "message": "Login successful.",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": "e6a2bc34-45a7-4c12-98ab-8c9012345678",
      "email": "engineer@trustvault.local",
      "full_name": "Lead Security Engineer",
      "role": "OWNER"
    }
  }
  ```

### 3. Identity Verification (`Me`)
* **Endpoint:** `GET /api/auth/me`
* **Access:** Protected (Bearer JWT in `Authorization` header)
* **Headers:** `Authorization: Bearer <token>`
* **Response (`200 OK`):**
  ```json
  {
    "user": {
      "id": "e6a2bc34-45a7-4c12-98ab-8c9012345678",
      "email": "engineer@trustvault.local",
      "role": "OWNER"
    }
  }
  ```

---

## 7. Document API Endpoints (Day 3)

All document endpoints require `Authorization: Bearer <token>` header.

### 1. Upload Document (Encrypted)
* **Endpoint:** `POST /api/documents/upload`
* **Access:** Any authenticated role
* **Body:** `multipart/form-data` with field `document` (file), `title` (string), `category` (string)
* **Security:** File encrypted in-memory with AES-256-GCM before storage. Ciphertext uploaded to private bucket.
* **Response (`201 Created`):**
  ```json
  {
    "message": "Document uploaded and encrypted successfully.",
    "document": { "id": "...", "title": "...", "category": "...", "file_size": 1024, "owner_id": "..." }
  }
  ```

### 2. List Documents (Tenant-Isolated)
* **Endpoint:** `GET /api/documents`
* **Access:** Any authenticated role
* **Security:** Non-ADMIN users see only documents they own or have an active grant for. Server constructs all filters — no client-supplied query params trusted.
* **Response (`200 OK`):**
  ```json
  { "documents": [ { "id": "...", "title": "...", "category": "...", "owner_id": "..." } ] }
  ```

### 3. Download Document (PEP-Authorized Streaming)
* **Endpoint:** `GET /api/documents/:id/download`
* **Access:** Document owner, ADMIN, or user with active `document_grants` row
* **Security:** Three-gate live DB authorization check per request. Decrypted in-memory. Never exposes raw storage URLs.
* **Response (`200 OK`):** Binary file buffer with appropriate `Content-Type` and `Content-Disposition` headers.
* **Denied Response (`403 Forbidden`):**
  ```json
  { "error": "Access denied: Insufficient document permissions." }
  ```

### 4. Delete Document
* **Endpoint:** `DELETE /api/documents/:id`
* **Access:** Document owner or ADMIN only
* **Security:** PEP check enforced. Deletes blob from storage, removes DB record (cascades grants), logs `DOCUMENT_DELETED` to audit trail.
* **Response (`200 OK`):**
  ```json
  { "message": "Document deleted successfully.", "id": "..." }
  ```

---

## 8. Grant Delegation & Audit API Endpoints (Day 4)

All grant and audit endpoints require `Authorization: Bearer <token>` header.

### 1. Create Document Access Grant
* **Endpoint:** `POST /api/grants`
* **Access:** Document owner or ADMIN
* **Request Body:**
  ```json
  {
    "documentId": "4c3b8e12-3456-4abc-8def-123456789abc",
    "granteeEmail": "viewer@trustvault.local"
  }
  ```
* **Security:** Enforces owner/admin authorization gate, prevents self-granting (`400 Bad Request`), checks user existence (`404`), blocks duplicate grants (`409 Conflict`), and logs `GRANT_CREATED` to audit trail.
* **Response (`201 Created`):**
  ```json
  {
    "message": "Access grant created successfully.",
    "grant": {
      "id": "7d2e1a34-bc56-4789-9012-abcdef123456",
      "document_id": "4c3b8e12-3456-4abc-8def-123456789abc",
      "grantee_id": "8f3a2b1c-4d5e-4678-8901-abcdef987654",
      "granted_to": "viewer@trustvault.local",
      "permission": "READ"
    }
  }
  ```

### 2. Revoke Document Access Grant (Immediate Invalidation)
* **Endpoint:** `DELETE /api/grants/:id`
* **Access:** Document owner, grant creator, or ADMIN
* **Security:** Deletes grant row from `document_grants`, immediately terminating download rights at the live PEP gate with zero caching latency. Logs `GRANT_REVOKED` to audit trail.
* **Response (`200 OK`):**
  ```json
  { "message": "Grant revoked successfully.", "grantId": "7d2e1a34-bc56-4789-9012-abcdef123456" }
  ```

### 3. List Document Access Grants
* **Endpoint:** `GET /api/grants/document/:documentId`
* **Access:** Document owner or ADMIN only
* **Response (`200 OK`):**
  ```json
  {
    "grants": [
      {
        "id": "7d2e1a34-bc56-4789-9012-abcdef123456",
        "document_id": "4c3b8e12-3456-4abc-8def-123456789abc",
        "grantee_id": "8f3a2b1c-4d5e-4678-8901-abcdef987654",
        "grantee_email": "viewer@trustvault.local",
        "permission": "READ"
      }
    ]
  }
  ```

### 4. Query Security Audit Logs
* **Endpoint:** `GET /api/audit-logs`
* **Access:** ADMIN role only (Double-layered PEP enforcement)
* **Query Parameters:** `page` (default 1), `limit` (default 50, max 100), `action`, `actorId` (UUID), `documentId` (UUID), `startDate` (ISO 8601), `endDate` (ISO 8601)
* **Security:** Clamps limit to prevent DoS, sanitizes UUID and date parameters, queries against indexed `timestamp` column.
* **Response (`200 OK`):**
  ```json
  {
    "data": [
      {
        "id": "e7b8a1c2-3d4e-4f5a-8b9c-0123456789ab",
        "timestamp": "2026-10-22T08:00:00.000Z",
        "created_at": "2026-10-22T08:00:00.000Z",
        "actor_id": "8f3a2b1c-4d5e-4678-8901-abcdef987654",
        "action": "GRANT_CREATED",
        "document_id": "4c3b8e12-3456-4abc-8def-123456789abc",
        "details": { "granteeEmail": "viewer@trustvault.local", "status": "SUCCESS" }
      }
    ],
    "count": 185,
    "page": 1,
    "totalPages": 4
  }
  ```

---

## 9. Health & Perimeter Defense Endpoints (Day 5)

### 1. Public Health Probe
* **Endpoint:** `GET /health`
* **Access:** Public (no authentication required)
* **Response (`200 OK`):**
  ```json
  {
    "status": "healthy",
    "timestamp": "2026-10-23T04:20:00.000Z",
    "uptime": 45.67
  }
  ```

### 2. Rate Limiting Protection
* **Auth Rate Limiting:** Applied to `/api/auth/login` and `/api/auth/register`. Caps traffic to **10 requests per 15 minutes** per IP. Exceeding attempts triggers HTTP `429 Too Many Requests`.
* **Global Rate Limiting:** Applied to all `/api/*` endpoints. Caps traffic to **200 requests per 15 minutes** per IP.
* **Input Sanitization:** Automatically strips script injection tags (`<script>`), null bytes (`\0`), HTML tags, and `javascript:` pseudo-protocols across all request bodies, query strings, and URL parameters.

---

## 10. Running the Test Suite

```bash
npm test
```

**Total: 90 automated tests across 9 suites (100% passing):**
| Suite | Tests | Coverage |
|---|---|---|
| `authUtils.test.js` | 10 | bcrypt hashing, JWT sign/verify, token error codes |
| `middleware.test.js` | 11 | PEP auth middleware, RBAC enforcement, audit log writes |
| `authRoutes.test.js` | 12 | Register/Login/Me endpoints, input validation, error responses |
| `cryptoUtils.test.js` | 9 | AES-256-GCM encrypt/decrypt, IV uniqueness, auth tag tampering |
| `storageService.test.js` | 6 | Multer 10MB limit, RAM-only buffer, storage CRUD operations |
| `documentRoutes.test.js` | 13 | BOLA prevention, tenant isolation, upload/download/delete PEP |
| `grantRoutes.test.js` | 14 | Grant delegation, instant revocation PEP check, non-owner blocking, self-grant rejection |
| `auditRoutes.test.js` | 11 | Admin-only RBAC, limit clamping, action/actor/date filtering, malformed parameter handling |
| `rateLimiter.test.js` | 4 | Public /health probe, input sanitization, 429 rate limit enforcement |

---

## 11. Vercel Single-Domain Deployment Configuration (Day 6)

TrustVault is configured for zero-friction single-domain deployment on Vercel:

### 1. Root `vercel.json` Routing
* **Serverless Backend:** `src/server.js` is bundled via `@vercel/node`.
* **Frontend SPA:** `client/package.json` is compiled with `@vercel/vite`.
* **Path Routing Rules:**
  * `/api/(.*)` $\to$ routed directly to `src/server.js` (Express REST API).
  * `/health` $\to$ routed directly to `src/server.js` (Public liveness probe).
  * `/(.*)` $\to$ routed to static frontend assets (`/client/$1`) with client-side SPA fallback.

### 2. Serverless Execution Handling
In `src/server.js`, `app.listen()` is executed conditionally:
```javascript
if (process.env.NODE_ENV !== 'test' && !process.env.VERCEL) {
  app.listen(PORT, ...);
}
export default app;
```
This guarantees smooth serverless invocation under Vercel's lifecycle without hung ports or cold-start timeouts.

### 3. Unified Frontend API Client
The React 19 frontend API client (`client/src/api/client.js`) defaults to relative `/api` when `VITE_API_BASE_URL` is omitted. Under local development, Vite's dev server proxies `/api` to `http://localhost:5000`; on Vercel, requests route natively to the Express serverless function on the same origin.

### 4. Required Vercel Environment Variables
Set the following in the **Vercel Project Settings $\to$ Environment Variables**:
* `SUPABASE_URL`: Supabase project URL (`https://<project-ref>.supabase.co`)
* `SUPABASE_SERVICE_ROLE_KEY`: Secret service role key for database PEP bypass & storage management
* `JWT_SECRET`: Minimum 32-character secret key for HMAC-SHA256 tokens
* `MASTER_ENCRYPTION_KEY`: 64-character hexadecimal string representing 32-byte AES-256 key
* `SUPABASE_STORAGE_BUCKET`: `vault-documents`
* `NODE_ENV`: `production`

---

## 12. Security Documentation

* [`PROMPTS.md`](./PROMPTS.md): AI interaction audit log across Days 1–6, documenting AI-generated security flaws, design decisions, and corrective human engineering.
* [`THREATS.md`](./THREATS.md): STRIDE + OWASP API 2023 threat register — 15 threat vectors (TV-01 to TV-15) covering audit immutability, BOLA, path traversal, JWT forgery, credential stuffing, AES-GCM misuse, malicious file uploads, delegation BOLA, self-granting, audit log DoS, brute-force rate limiting, and input sanitization.
