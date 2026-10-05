-- Review this policy adaptation before use. The runner has already created
-- fixture.records(id integer, tenant_id text, value text) and two synthetic rows.
-- This reproduces an RLS rule; it does not import a deployed database.
GRANT SELECT, INSERT, UPDATE, DELETE ON fixture.records TO tr_tenant_a, tr_tenant_b;
ALTER TABLE fixture.records ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_access ON fixture.records
  TO tr_tenant_a, tr_tenant_b
  USING (tenant_id = current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id')
  WITH CHECK (tenant_id = current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id');
