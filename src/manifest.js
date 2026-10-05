export const CHECKS = Object.freeze({
  'owner-read': 'An owner can read their own record',
  'cross-tenant-read': 'A different tenant cannot read the record',
  'anonymous-read': 'An unauthenticated actor cannot read the record',
  'literal-input': 'A hostile record key cannot broaden the lookup',
  'postgres-rls': 'Database policies enforce both allowed and denied operations',
  'agent-injection': 'Untrusted content cannot trigger privileged agent actions'
});
const id = /^[a-z][a-z0-9-]{0,63}$/;
function object(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(k => Object.hasOwn(value, k));
}
export function validateManifest(m) {
  const invalid = () => { throw new Error('Invalid manifest: use the documented version 1 schema.'); };
  if (!object(m, ['version', 'feature', 'threats']) || m.version !== 1 || typeof m.feature !== 'string' || !id.test(m.feature)
    || !Array.isArray(m.threats) || m.threats.length < 1 || m.threats.length > 32) invalid();
  const ids = new Set();
  for (const t of m.threats) {
    if (!object(t, ['id', 'check']) || typeof t.id !== 'string' || !id.test(t.id) || t.id.startsWith('coverage-') || ids.has(t.id)
      || typeof t.check !== 'string' || !Object.hasOwn(CHECKS, t.check)) invalid();
    ids.add(t.id);
  }
  // Negative checks alone could approve an implementation that denies everything.
  const required = ['owner-read', 'cross-tenant-read', 'anonymous-read', 'literal-input'];
  if (!required.every(c => m.threats.some(t => t.check === c))) invalid();
  return m;
}
