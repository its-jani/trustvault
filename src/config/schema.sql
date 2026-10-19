-- ==============================================================================
-- TrustVault Security-First Document Platform - Production Database Schema
-- Day 1 Foundation: Users, Documents, Grants, Audit Logs & Immutability Trigger
-- ==============================================================================

-- 1. Enable Required Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Define Custom Security Enums
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('ADMIN', 'OWNER', 'VIEWER');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE grant_permission AS ENUM ('READ', 'EDIT');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 3. Users Table (Core Identities & Roles)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'VIEWER',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Documents Table (Metadata & Storage Pointers)
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

-- 5. Document Grants Table (Explicit Per-User Access Grants)
CREATE TABLE IF NOT EXISTS document_grants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    grantee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission grant_permission NOT NULL,
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_document_grantee UNIQUE (document_id, grantee_id)
);

-- 6. Audit Logs Table (Tamper-Evident, Append-Only Forensic Records)
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

-- 7. High-Performance Indexes
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
CREATE INDEX IF NOT EXISTS idx_grants_lookup ON document_grants(document_id, grantee_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_document ON audit_logs(document_id);

-- 8. PostgreSQL Immutability Trigger (Zero-Tolerance Rule #3 Enforcement)
CREATE OR REPLACE FUNCTION prevent_audit_log_alteration()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'TRUSTVAULT_SECURITY_VIOLATION: The audit_logs table is append-only. Modification (UPDATE) or deletion (DELETE) is strictly prohibited by security policy.'
        USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_audit_log_alteration ON audit_logs;

CREATE TRIGGER trg_prevent_audit_log_alteration
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_alteration();
