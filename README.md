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
├── README.md                  # Project overview and runbook
├── PROMPTS.md                 # AI prompt log, vulnerability analysis, and fixes (7 entries)
├── THREATS.md                 # STRIDE threat model & attack vector register (TV-01 → TV-09)
├── tests/
│   ├── authUtils.test.js      # Password & JWT cryptographic unit tests (10 tests)
│   ├── middleware.test.js     # PEP authentication & RBAC middleware tests (11 tests)
│   ├── authRoutes.test.js     # Auth API routes integration tests (12 tests)
│   ├── cryptoUtils.test.js    # AES-256-GCM crypto utilities unit tests (9 tests)
│   ├── storageService.test.js # Multer ingestion & storage service tests (6 tests)
│   └── documentRoutes.test.js # Document API PEP access enforcement tests (13 tests)
└── src/
    ├── config/
    │   ├── env.js             # Validated environment configurations (JWT, AES, Supabase)
    │   ├── schema.sql         # Supabase PostgreSQL schema DDL with immutability trigger
    │   └── supabase.js        # Headless Supabase client with Service Role authorization
    ├── controllers/
    │   ├── authController.js  # Registration, login, and identity controllers
    │   └── documentController.js # Upload, download, list, delete controllers with PEP
    ├── middleware/
    │   ├── auth.js            # PEP Bearer JWT authentication & audit logger
    │   ├── errorHandler.js    # Centralized Express error handler (no stack leaks in prod)
    │   ├── rbac.js            # Policy Enforcement Point RBAC authorization
    │   └── upload.js          # In-memory Multer middleware (RAM-only, 10MB limit)
    ├── routes/
    │   ├── authRoutes.js      # Public/protected auth route definitions
    │   └── documentRoutes.js  # PEP-protected document route definitions
    ├── services/
    │   └── storageService.js  # Private Supabase Storage CRUD (upload/download/delete)
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

## 8. Running the Test Suite

```bash
npm test
```

**Total: 61 automated tests across 6 suites:**
| Suite | Tests | Coverage |
|---|---|---|
| `authUtils.test.js` | 10 | bcrypt hashing, JWT sign/verify, token error codes |
| `middleware.test.js` | 11 | PEP auth middleware, RBAC enforcement, audit log writes |
| `authRoutes.test.js` | 12 | Register/Login/Me endpoints, input validation, error responses |
| `cryptoUtils.test.js` | 9 | AES-256-GCM encrypt/decrypt, IV uniqueness, auth tag tampering |
| `storageService.test.js` | 6 | Multer 10MB limit, RAM-only buffer, storage CRUD operations |
| `documentRoutes.test.js` | 13 | BOLA prevention, tenant isolation, upload/download/delete PEP |

---

## 9. Security Documentation

* [`PROMPTS.md`](./PROMPTS.md): 7-entry AI interaction audit log across Days 1–3, documenting AI-generated security flaws and corrective human engineering.
* [`THREATS.md`](./THREATS.md): STRIDE + OWASP API 2023 threat register — 9 threat vectors (TV-01 to TV-09) covering audit immutability, BOLA, path traversal, JWT forgery, credential stuffing, AES-GCM misuse, and malicious file uploads.
