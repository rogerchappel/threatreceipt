import { createHash } from 'node:crypto';

export const builtInSQL = profile => `
GRANT SELECT, INSERT, UPDATE, DELETE ON fixture.records TO tr_tenant_a, tr_tenant_b;
ALTER TABLE fixture.records ENABLE ROW LEVEL SECURITY;
${profile === 'deny-all' ? '' : `CREATE POLICY tenant_access ON fixture.records TO tr_tenant_a, tr_tenant_b USING (${profile === 'permissive' ? 'true' : "tenant_id = current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id'"}) WITH CHECK (${profile === 'permissive' ? 'true' : "tenant_id = current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id'"});`}
`;
// External SQL loading is disabled pending independent privilege-boundary review.
// Keep rejecting legacy options so older commands cannot silently fall back.
export async function postgresInput(profile, root, sqlFile, accept) {
  if (!['secure','permissive','deny-all'].includes(profile) || root || sqlFile || accept)
    throw new Error('Only bundled PostgreSQL fixtures are supported. Reviewed SQL is disabled.');
  const sql=builtInSQL(profile);
  return {profile,sql,sha256:createHash('sha256').update(sql).digest('hex')};
}
