import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { requestFixture, runChecks } from '../src/runner.js';
const manifest = JSON.parse(readFileSync(new URL('../examples/shortlist.json',import.meta.url)));
async function serverTest(handler, check) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  try { await check(`http://127.0.0.1:${server.address().port}`); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
test('bounded response and deadline reject oversized and stalled replies', async () => {
  await serverTest((_req,res) => res.end('x'.repeat(8193)), async origin => {
    const request = await requestFixture(origin,'/records?id=alpha');
    await assert.rejects(request('tenant-a'), /Response too large/);
  });
  await serverTest(() => {}, async origin => {
    const request = await requestFixture(origin,'/records?id=alpha');
    await assert.rejects(request('tenant-a'), /deadline exceeded/);
  });
});
test('deny-all implementation cannot pass the positive owner invariant', async () => {
  await serverTest((_req,res) => { res.writeHead(403); res.end('{"error":"forbidden"}'); }, async origin => {
    const report = await runChecks(manifest,origin,true);
    assert.equal(report.results.find(r => r.check === 'owner-read').status,'fail');
    assert.equal(report.summary.pass,1);
  });
});
test('CLI executes both fixtures reproducibly with no raw fixture data', () => {
  for (const profile of ['secure','vulnerable']) {
    const run = () => spawnSync(process.execPath,['bin/threatreceipt.js','run','examples/shortlist.json','--fixture',profile,'--execute','--format','json'],{encoding:'utf8',timeout:10000});
    const a=run(),b=run();
    assert.equal(a.status,profile === 'secure' ? 2 : 1);
    assert.equal(a.stdout,b.stdout);
    assert.doesNotMatch(a.stdout,/synthetic-only|127\.0\.0\.1|\/Users\//);
  }
});
