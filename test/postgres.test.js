import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, rm, access, mkdir, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { postgresBinaries, startPostgres, boundedProcess, supportedPostgresVersion } from '../src/postgres-cluster.js';
import { postgresInput } from '../src/postgres-input.js';
import { runPostgres, tenantRoleSafe } from '../src/postgres.js';
let available=false;
try {await postgresBinaries(); available=true;} catch {}
if(process.env.THREATRECEIPT_REQUIRE_POSTGRES==='1' && !available) throw new Error('Required PostgreSQL 16.15+ runtime unavailable.');
const pg={skip:!available};
const input=profile=>postgresInput(profile,undefined,undefined,false);
const success=report=>{
 assert.equal(report.checks.length,21);
 assert.ok(report.checks.every(c=>c.status==='pass'),JSON.stringify(report.checks));
 assert.deepEqual(report.cleanup,{stopped:true,removed:true});
};

test('real PostgreSQL enforces both tenants CRUD and detects policy mutation controls',pg,async()=>{
 success(await runPostgres(await input('secure')));
 for(const profile of ['permissive','deny-all']) {
  const result=await runPostgres(await input(profile));
  assert.equal(result.checks.filter(c=>c.status==='fail').length,10);
  assert.equal(result.checks.filter(c=>c.status==='inconclusive').length,0);
  const own=result.checks.find(c=>c.id==='a-allow-select');
  const other=result.checks.find(c=>c.id==='a-deny-select');
  assert.equal(own.status,profile==='permissive'?'pass':'fail');
  assert.equal(other.status,profile==='permissive'?'fail':'pass');
  assert.deepEqual(result.cleanup,{stopped:true,removed:true});
 }
});
test('PostgreSQL security patch floor rejects older or unrecognized tools',()=>{
 for(const v of ['postgres (PostgreSQL) 16.13','psql (PostgreSQL) 16.14','postgres (PostgreSQL) 16.15beta1','postgres (PostgreSQL) 17.11','unknown 16.15']) assert.equal(supportedPostgresVersion(v),false);
 for(const v of ['postgres (PostgreSQL) 16.15','psql (PostgreSQL) 16.15 (Debian)','initdb (PostgreSQL) 16.16','pg_isready (PostgreSQL) 16.15']) assert.equal(supportedPostgresVersion(v),true);
});
test('external SQL and legacy reviewed options are disabled before any file or database access',async()=>{
 await assert.rejects(postgresInput('reviewed','/not-accessed','policy.sql',true),/disabled/);
 await assert.rejects(postgresInput('secure','/not-accessed','policy.sql',true),/disabled/);
 const base=await input('secure');
 for(const tampered of [{...base,profile:'reviewed'},{...base,sql:base.sql+'SELECT 1;'}]) {
  const report=await runPostgres(tampered);
  assert.equal(report.provenance.runtime,'unavailable');
  assert.match(report.checks.find(c=>c.id==='execution').evidence,/bundled-input/);
  assert.equal(report.checks.filter(c=>c.status==='pass').length,1); // cleanup only
 }
 const child=spawnSync(process.execPath,['bin/threatreceipt.js','run','examples/shortlist.json','--postgres','reviewed','--execute','--accept-reviewed-sql'],{encoding:'utf8',timeout:5000});
 assert.equal(child.status,64);
});
test('actual owner, superuser, BYPASSRLS and owner-member identities are refused',pg,async()=>{
 const cluster=await startPostgres();
 try {
  assert.equal((await cluster.sql('tr_bootstrap',"CREATE ROLE tr_fixture_owner; CREATE ROLE tr_tenant_a LOGIN NOSUPERUSER NOBYPASSRLS; CREATE SCHEMA fixture; CREATE TABLE fixture.records(id integer); ALTER TABLE fixture.records OWNER TO tr_fixture_owner; GRANT USAGE ON SCHEMA fixture TO tr_tenant_a;")).code,0);
  assert.equal(await tenantRoleSafe(cluster,'tr_tenant_a'),true);
  for(const change of ['ALTER ROLE tr_tenant_a BYPASSRLS;','ALTER ROLE tr_tenant_a SUPERUSER;','GRANT tr_fixture_owner TO tr_tenant_a;','ALTER TABLE fixture.records OWNER TO tr_tenant_a;']) {
   assert.equal((await cluster.sql('tr_bootstrap',change)).code,0);
   assert.equal(await tenantRoleSafe(cluster,'tr_tenant_a'),false);
   await cluster.sql('tr_bootstrap','ALTER ROLE tr_tenant_a NOSUPERUSER NOBYPASSRLS; REVOKE tr_fixture_owner FROM tr_tenant_a; ALTER TABLE fixture.records OWNER TO tr_fixture_owner;');
  }
 } finally {assert.deepEqual(await cluster.cleanup(),{stopped:true,removed:true});}
});
test('crashed server and cancellation cannot be mistaken for completed coverage',pg,async()=>{
 const cluster=await startPostgres();
 process.kill(cluster.pid,'SIGKILL'); await delay(50);
 try {const r=await cluster.sql('tr_bootstrap','SELECT 1;');assert.notEqual(r.code,0);}
 finally {assert.deepEqual(await cluster.cleanup(),{stopped:true,removed:true});await assert.rejects(access(cluster.root));}
 const controller=new AbortController();controller.abort();
 const result=await runPostgres(await input('secure'),{signal:controller.signal});
 assert.equal(result.checks.find(c=>c.id==='execution').status,'inconclusive');
 assert.deepEqual(result.cleanup,{stopped:true,removed:true});
});
test('cleanup reports a real filesystem failure instead of claiming removal',pg,async()=>{
 const cluster=await startPostgres();const blocked=join(cluster.root,'blocked');
 await mkdir(blocked);await writeFile(join(blocked,'file'),'synthetic');await chmod(blocked,0);
 try {
  const result=await cluster.cleanup();
  assert.equal(result.stopped,true);
  assert.equal(result.removed,false);
 } finally {await chmod(blocked,0o700);await rm(cluster.root,{recursive:true,force:true});}
});
test('CLI verifies bundled policy provenance without inherited database targets',pg,async()=>{
 const r=spawnSync(process.execPath,['bin/threatreceipt.js','run','examples/shortlist.json','--execute','--postgres','secure','--application-commit','a'.repeat(40),'--format','json'],{encoding:'utf8',timeout:20000,env:{...process.env,PGHOST:'production.invalid',PGPORT:'1',PGDATABASE:'CANARY_DB',PGUSER:'CANARY_USER',PGPASSWORD:'CANARY_SECRET',PGOPTIONS:'-c role=tr_bootstrap'}});
 assert.equal(r.status,2,r.stderr);
 const report=JSON.parse(r.stdout);
 assert.deepEqual(report.summary,{pass:25,fail:0,inconclusive:1});
 assert.equal(report.provenance.adapters[1].fixture,'secure');
 assert.equal(new Set(report.results.map(r=>r.threat)).size,report.results.length);
 assert.doesNotMatch(r.stdout+r.stderr,/CANARY|production\.invalid|\/Users\/|\/tmp\/|synthetic-a/);
});
test('bounded subprocess timeout and output limits do not leak process output',async()=>{
 await assert.rejects(boundedProcess(process.execPath,['-e','setTimeout(()=>{},10000)'],{},50),/deadline/);
 await assert.rejects(boundedProcess(process.execPath,['-e',"process.stdout.write('x'.repeat(70000))"],{},2000),/output limit/);
});
