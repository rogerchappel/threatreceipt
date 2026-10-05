import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { validateManifest } from '../src/manifest.js';
import { runChecks, requestFixture, exitCode } from '../src/runner.js';
import { startFixture } from '../src/fixture.js';
import { formatReport } from '../src/reports.js';
const manifest = JSON.parse(readFileSync(new URL('../examples/shortlist.json', import.meta.url)));
const cli = (args) => spawnSync(process.execPath, ['bin/threatreceipt.js', ...args], { encoding:'utf8', timeout:10000 });

test('secure and vulnerable fixtures demonstrate real HTTP outcomes', async () => {
  for (const [profile, summary, code] of [ ['secure', {pass:4, fail:0, inconclusive:2}, 2], ['vulnerable', {pass:1, fail:3, inconclusive:2}, 1] ]) {
    const fixture = await startFixture(profile);
    try {
      const report = await runChecks(manifest, fixture.origin, true);
      assert.deepEqual(report.summary, summary);
      assert.equal(exitCode(report), code);
      assert.match(formatReport(report, 'junit'), /skipped="2"/);
    } finally { await fixture.close(); }
  }
});
test('dry run never needs a target and cannot become a success', async () => {
  const r = await runChecks(manifest, 'https://production.invalid', false);
  assert.deepEqual(r.summary, {pass:0, fail:0, inconclusive:6});
  assert.equal(exitCode(r), 2);
  const child = cli(['run', 'examples/shortlist.json', '--format', 'json']);
  assert.equal(child.status, 2);
  assert.equal(JSON.parse(child.stdout).mode, 'dry-run');
});
test('manifest rejects unknown code, targets, credentials and reduced negative-only suites', () => {
  for (const mutation of [
    m => m.target = 'http://127.0.0.1:8080',
    m => m.command = 'curl attacker.invalid',
    m => m.token = 'CANARY_SECRET',
    m => m.threats[0].check = '__proto__',
    m => m.threats[0].check = 'shell',
    m => m.threats[0].expected = 200,
    m => m.threats[0].id = '<script/>',
    m => m.threats[0].id = m.threats[1].id,
    m => m.threats.shift(),
    m => m.threats = [],
    m => m.version = 2,
    m => m.feature = '../secret',
    m => m.feature = null
  ]) {
    const m = structuredClone(manifest); mutation(m);
    assert.throws(() => validateManifest(m), /Invalid manifest/);
  }
  assert.throws(() => validateManifest(null));
});
test('unsupported coverage remains visible when omitted', async () => {
  const m = structuredClone(manifest); m.threats = m.threats.slice(0,4);
  validateManifest(m);
  const r = await runChecks(m, undefined, false);
  assert.equal(r.results.length, 6);
});
test('CLI rejects ambiguous options and never echoes secrets or paths', () => {
  const dir = mkdtempSync(join(tmpdir(), 'threatreceipt-test-'));
  try {
    const file = join(dir, 'CANARY_PRIVATE_PATH.json');
    writeFileSync(file, JSON.stringify({...manifest, token:'CANARY_SECRET'}));
    for (const args of [
      ['run', file],
      ['run', 'examples/shortlist.json', '--target', 'https://example.com'],
      ['run', 'examples/shortlist.json', '--fixture', 'secure', '--fixture', 'vulnerable'],
      ['run', 'examples/shortlist.json', '--format', 'shell'],
      ['run', 'examples/shortlist.json', '--execute', '--execute'],
      ['run', 'examples/shortlist.json', '--fixture'],
      ['run', '/dev/null']
    ]) {
      const r = cli(args); assert.equal(r.status,64);
      assert.doesNotMatch(r.stdout+r.stderr, /CANARY|\/Users\/|https:\/\//);
    }
    writeFileSync(file, 'x'.repeat(16385)); assert.equal(cli(['run',file]).status,64);
  } finally { rmSync(dir,{recursive:true,force:true}); }
});
test('request boundary blocks network targets and rejects redirects without following', async () => {
  for (const origin of ['https://127.0.0.1:1234','http://localhost:1234','http://127.1:1234@evil.invalid','http://[::1]:1234','http://127.0.0.1:1234/path','http://127.0.0.1:1234?secret'])
    await assert.rejects(requestFixture(origin, '/records?id=alpha'));
  let requests = 0;
  const server = http.createServer((_req,res) => { requests++; res.writeHead(302,{location:'http://127.0.0.1:1/secret'}); res.end(); });
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  try {
    const request = await requestFixture(`http://127.0.0.1:${server.address().port}`, '/records?id=alpha');
    await assert.rejects(request('tenant-a'), /Redirect rejected/);
    assert.equal(requests,1);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
test('denial status with leaked data fails; raw response never enters evidence', async () => {
  const server = http.createServer((_req,res) => { res.writeHead(403); res.end(JSON.stringify({records:[{secret:'CANARY_SECRET'}]})); });
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  try {
    const r = await runChecks(manifest, `http://127.0.0.1:${server.address().port}`, true);
    assert.equal(r.summary.fail,4);
    for (const fmt of ['human','json','junit']) assert.doesNotMatch(formatReport(r,fmt), /CANARY_SECRET/);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
test('transport failure is inconclusive, not pass; XML escapes metadata', async () => {
  const fixture = await startFixture('secure'); const origin = fixture.origin; await fixture.close();
  const r = await runChecks(manifest,origin,true);
  assert.equal(r.summary.inconclusive,6);
  assert.equal(r.summary.pass,0);
  r.feature = '<&"';
  assert.match(formatReport(r,'junit'), /&lt;&amp;&quot;/);
});
