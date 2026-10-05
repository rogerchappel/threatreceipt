import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import { validateManifest } from '../src/manifest.js';
import { runChecks } from '../src/runner.js';
import { formatReport } from '../src/reports.js';
const manifest=JSON.parse(readFileSync(new URL('../examples/shortlist.json',import.meta.url)));
test('positive owner response rejects additional fields at every allowed level', async () => {
  for (const body of [
    {records:[{id:'alpha',tenant:'tenant-a',value:'synthetic-only',secret:'CANARY'}]},
    {records:[{id:'alpha',tenant:'tenant-a',value:'synthetic-only'}],secret:'CANARY'}
  ]) {
    const server=http.createServer((_req,res)=>{res.end(JSON.stringify(body));});
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    try {
      const r=await runChecks(manifest,`http://127.0.0.1:${server.address().port}`,true);
      assert.equal(r.results[0].status,'fail');
      assert.doesNotMatch(JSON.stringify(r),/CANARY/);
    } finally { await new Promise(resolve=>server.close(resolve)); }
  }
});
test('reserved generated IDs cannot collide with declared threats', async () => {
  const m=structuredClone(manifest);m.threats[0].id='coverage-postgres-rls';
  assert.throws(()=>validateManifest(m));
  const r=await runChecks(manifest,undefined,false);
  assert.equal(new Set(r.results.map(x=>x.threat)).size,r.results.length);
});
test('receipts bind canonical manifest, tool, adapter and optional declared revision', async () => {
  const context={httpFixture:'secure',applicationCommit:'a'.repeat(40)};
  const a=await runChecks(manifest,undefined,false,context);
  const m=structuredClone(manifest);m.feature='changed-feature';
  const b=await runChecks(m,undefined,false,context);
  assert.match(a.provenance.manifestSha256,/^[a-f0-9]{64}$/);
  assert.notEqual(a.provenance.manifestSha256,b.provenance.manifestSha256);
  assert.equal(a.provenance.applicationCommit.independentlyVerified,false);
  assert.equal(a.provenance.adapters[0].fixture,'secure');
  for (const fmt of ['json','human','junit']) assert.ok(formatReport(a,fmt).includes(a.provenance.manifestSha256));
});
