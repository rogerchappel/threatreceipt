import http from 'node:http';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
export const toolVersion = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const adapterDigest = createHash('sha256').update(readFileSync(new URL('./fixture.js', import.meta.url))).update(readFileSync(new URL('./runner.js', import.meta.url))).digest('hex');
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])])) : value;
const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
import { CHECKS } from './manifest.js';
// No redirects, DNS, proxy environment variables, cookies, or arbitrary targets.
export async function requestFixture(origin, path) {
  const base = new URL(origin);
  if (base.protocol !== 'http:' || base.hostname !== '127.0.0.1' || !base.port
      || base.username || base.password || base.pathname !== '/' || base.search || base.hash)
    throw new Error('Target is outside the loopback fixture allowlist.');
  if (!path.startsWith('/records?') || path.includes('#')) throw new Error('Invalid fixture request.');
  return async actor => new Promise((resolve, reject) => {
    const req = http.get(new URL(path, base), {
      headers: actor ? { 'x-demo-actor': actor } : {},
      agent: false
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400) {
        res.destroy(); reject(new Error('Redirect rejected.')); return;
      }
      let body = '';
      res.on('data', data => {
        body += data.toString('utf8');
        if (Buffer.byteLength(body) > 8192) { res.destroy(); reject(new Error('Response too large.')); }
      });
      res.on('error', reject);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }); }
        catch { reject(new Error('Invalid fixture response.')); }
      });
    });
    const deadline = setTimeout(() => req.destroy(new Error('Fixture deadline exceeded.')), 2000);
    req.on('close', () => clearTimeout(deadline));
    req.on('error', reject);
  });
}
export async function runChecks(manifest, origin, execute, context = {}) {
  const results = [];
  for (const threat of manifest.threats) {
    const result = { threat: threat.id, check: threat.check, invariant: CHECKS[threat.check], status: 'inconclusive', evidence: 'Not executed (dry run).' };
    if (execute) {
      if (threat.check === 'postgres-rls' && context.postgresReport) {
        for (const item of context.postgresReport.checks) results.push({threat: `${threat.id}:${item.id}`, check: threat.check, invariant: CHECKS[threat.check], status: item.status, evidence: item.evidence});
        continue;
      } else if (['postgres-rls', 'agent-injection'].includes(threat.check)) {
        result.evidence = 'Adapter unavailable; no coverage claimed.';
      } else {
        try {
          const key = threat.check === 'literal-input' ? "alpha' OR '1'='1" : 'alpha';
          const actor = threat.check === 'anonymous-read' ? undefined : threat.check === 'cross-tenant-read' ? 'tenant-b' : 'tenant-a';
          const request = await requestFixture(origin, '/records?id=' + encodeURIComponent(key));
          const actual = await request(actor);
          const expected = { 'owner-read': 200, 'cross-tenant-read': 403, 'anonymous-read': 401, 'literal-input': 404 }[threat.check];
          const records = actual.body?.records;
          const allowed = threat.check === 'owner-read';
          const payloadOK = allowed
            ? exactKeys(actual.body, ['records']) && Array.isArray(records) && records.length === 1 && exactKeys(records[0], ['id', 'tenant', 'value']) && records[0]?.id === 'alpha' && records[0]?.tenant === 'tenant-a' && records[0]?.value === 'synthetic-only'
            : actual.body && !Array.isArray(actual.body) && Object.keys(actual.body).length === 1 && actual.body.error === ({401:'auth',403:'forbidden',404:'missing'}[expected]);
          result.status = actual.status === expected && payloadOK ? 'pass' : 'fail';
          result.evidence = `HTTP ${actual.status}; expected ${expected}; response contract ${payloadOK ? 'matched' : 'mismatched'}.`;
        } catch {
          result.evidence = 'Fixture transport or response invalid; protection unverified.';
        }
      }
    }
    results.push(result);
  }
  // Keep absent coverage visible even if omitted from the manifest.
  for (const check of ['postgres-rls', 'agent-injection']) {
    if (!results.some(r => r.check === check)) results.push({threat: 'coverage-' + check, check, invariant: CHECKS[check], status:'inconclusive', evidence:'Adapter unavailable; no coverage claimed.'});
  }
  const summary = Object.fromEntries(['pass', 'fail', 'inconclusive'].map(s => [s, results.filter(r => r.status === s).length]));
  return { schemaVersion: 2, provenance: { tool: { name: 'threatreceipt', version: toolVersion }, manifestSha256: createHash('sha256').update(JSON.stringify(canonical(manifest))).digest('hex'), adapters: [{ name: 'http-fixture', fixture: context.httpFixture ?? 'unspecified', sourceSha256: adapterDigest }, ...(context.postgresReport ? [context.postgresReport.provenance] : context.postgresPlanned ? [context.postgresPlanned] : [])], ...(context.applicationCommit ? {applicationCommit: {value: context.applicationCommit, independentlyVerified: false}} : {}) }, feature: manifest.feature, mode: execute ? 'executed' : 'dry-run', summary, results };
}
export function exitCode(report) { return report.summary.fail ? 1 : report.summary.inconclusive ? 2 : 0; }
