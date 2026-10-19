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
├── PROMPTS.md                 # AI prompt log, vulnerability analysis, and fixes
├── THREATS.md                 # STRIDE threat model & attack vector register
└── src/
    ├── config/
    │   ├── schema.sql         # Supabase PostgreSQL schema DDL with immutability trigger
    │   └── supabase.js        # Headless Supabase client with Service Role authorization
    ├── middleware/
    │   └── errorHandler.js    # Centralized Express error handler (no stack leaks in prod)
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

## 6. Security Documentation

* [`PROMPTS.md`](./PROMPTS.md): Documents the AI interactions, security flaws in generated SQL, and human-in-the-loop remediation.
* [`THREATS.md`](./THREATS.md): Comprehensive STRIDE analysis of Threat Vector 1 (Audit Trail Alteration) and Threat Vector 2 (Path Traversal & Storage Exposure).
