-- Folklore tenant isolation for PostgreSQL.
-- Apply with a migration role, not with the runtime application role.
-- The runtime role must not be a superuser, table owner, or BYPASSRLS role.

CREATE SCHEMA IF NOT EXISTS app;

CREATE TABLE IF NOT EXISTS app.tenants (
  id text PRIMARY KEY CHECK (id ~ '^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$'),
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.client_records (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES app.tenants(id),
  external_reference text NOT NULL,
  sanitized_summary text NOT NULL,
  -- Keep raw_payload only if the retention and encryption policy explicitly permits it.
  raw_payload jsonb,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.agent_messages (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES app.tenants(id),
  client_record_id uuid NOT NULL REFERENCES app.client_records(id),
  recipient_agent text NOT NULL,
  need_summary text NOT NULL,
  allowed_fields text[] NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- The application sets this only inside a transaction after verifying the OIDC token.
-- Missing or empty context intentionally returns NULL and therefore matches no tenant row.
CREATE OR REPLACE FUNCTION app.current_tenant_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')
$$;

ALTER TABLE app.client_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.client_records FORCE ROW LEVEL SECURITY;
ALTER TABLE app.agent_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.agent_messages FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS client_records_tenant_isolation ON app.client_records;
CREATE POLICY client_records_tenant_isolation
  ON app.client_records
  FOR ALL
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());

DROP POLICY IF EXISTS agent_messages_tenant_isolation ON app.agent_messages;
CREATE POLICY agent_messages_tenant_isolation
  ON app.agent_messages
  FOR ALL
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (
    tenant_id = app.current_tenant_id()
    AND EXISTS (
      SELECT 1
      FROM app.client_records record
      WHERE record.id = client_record_id
        AND record.tenant_id = app.current_tenant_id()
    )
  );

-- Do not grant runtime access to the public role. Replace folklore_app with the
-- least-privilege role used by the API connection pool.
REVOKE ALL ON SCHEMA app FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA app FROM PUBLIC;
GRANT USAGE ON SCHEMA app TO folklore_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.client_records, app.agent_messages TO folklore_app;
GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO folklore_app;

-- A request must set context on the same pooled connection and inside the same
-- transaction as the protected query. The third argument TRUE makes the setting
-- transaction-local and prevents context leakage to the next request.
--
-- BEGIN;
-- SELECT set_config('app.tenant_id', 'tenant-alpha', true);
-- SELECT id, external_reference, sanitized_summary
-- FROM app.client_records;
-- COMMIT;
