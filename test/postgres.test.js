import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, writeFile, rm, access, symlink, mkdir, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { postgresBinaries, startPostgres, boundedProcess } from '../src/postgres-cluster.js';
import { postgresInput } from '../src/postgres-input.js';
import { runPostgres, tenantRoleSafe } from '../src/postgres.js';
let available=false;
try {await postgresBinaries(); available=true;} catch {}
if(process.env.THREATRECEIPT_REQUIRE_POSTGRES==='1' && !available) throw new Error('Required PostgreSQL 16 runtime unavailable.');
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
test('reviewed fixture is opted in, bounded and cannot use external paths or symlinks',async()=>{
 const root=await mkdtemp(join(await realpath(tmpdir()),'tr-input-'));
 try {
  await writeFile(join(root,'policy.sql'),(await input('secure')).sql);
  await assert.rejects(postgresInput('reviewed',root,'policy.sql',false));
  await assert.rejects(postgresInput('reviewed',root,'../policy.sql',true));
  await assert.rejects(postgresInput('reviewed',root,join(root,'policy.sql'),true));
  await symlink(join(root,'policy.sql'),join(root,'link.sql'));
  await assert.rejects(postgresInput('reviewed',root,'link.sql',true));
  await writeFile(join(root,'large.sql'),'x'.repeat(32769));
  await assert.rejects(postgresInput('reviewed',root,'large.sql',true));
  await writeFile(join(root,'bad.sql'),Buffer.from([255]));
  await assert.rejects(postgresInput('reviewed',root,'bad.sql',true));
  const reviewed=await postgresInput('reviewed',root,'policy.sql',true);
  assert.equal(reviewed.sha256,(await input('secure')).sha256);
  if(available) success(await runPostgres(reviewed));
 } finally {await rm(root,{recursive:true,force:true});}
});
test('SQL is a restricted server command, never psql shell or elevated program execution',pg,async()=>{
 const root=await mkdtemp(join(await realpath(tmpdir()),'tr-sql-'));
 const marker=join(root,'must-not-exist');
 try {
  for(const sql of [`\\! touch ${marker}`,`COPY (SELECT 1) TO PROGRAM 'touch ${marker}';`,'ALTER ROLE tr_tenant_a SUPERUSER;','SET ROLE tr_bootstrap;']) {
   await writeFile(join(root,'policy.sql'),sql);
   const result=await runPostgres(await postgresInput('reviewed',root,'policy.sql',true));
   assert.equal(result.checks.find(c=>c.id==='execution').status,'inconclusive');
   assert.deepEqual(result.cleanup,{stopped:true,removed:true});
   await assert.rejects(access(marker));
  }
 } finally {await rm(root,{recursive:true,force:true});}
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
test('in-transaction state evidence catches trigger writes to a forbidden tenant',pg,async()=>{
 const base=await input('secure');
 const sql=base.sql+`
 CREATE FUNCTION fixture.bad_side_effect() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
 BEGIN
 IF pg_trigger_depth()=1 THEN UPDATE fixture.records SET value='unexpected' WHERE id=2; END IF;
 RETURN NULL;
 END; $$;
 CREATE TRIGGER corrupt_other AFTER UPDATE ON fixture.records FOR EACH STATEMENT EXECUTE FUNCTION fixture.bad_side_effect();`;
 const report=await runPostgres({...base,sql});
 assert.equal(report.checks.find(c=>c.id==='a-allow-update').status,'fail');
 assert.equal(report.checks.find(c=>c.id==='a-deny-update').status,'fail');
 assert.deepEqual(report.cleanup,{stopped:true,removed:true});
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
test('SQL deadlines and an early backend termination produce inconclusive receipts with cleanup',pg,async()=>{
 for(const sql of ["SELECT pg_sleep(5);", "SET statement_timeout=0; SELECT pg_sleep(15);",'SELECT pg_terminate_backend(pg_backend_pid());']) {
  const base=await input('secure');const started=Date.now();
  const r=await runPostgres({...base,sql});
  assert.equal(r.checks.find(c=>c.id==='execution').status,'inconclusive');
  assert.deepEqual(r.cleanup,{stopped:true,removed:true});
  assert.ok(Date.now()-started<10000);
 }
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
test('CLI verifies reviewed policy SQL and provenance without inherited database targets',pg,async()=>{
 const r=spawnSync(process.execPath,['bin/threatreceipt.js','run','examples/shortlist.json','--execute','--postgres','reviewed','--fixture-root',await realpath('.'),'--reviewed-sql','examples/postgres/reviewed-policy.sql','--accept-reviewed-sql','--application-commit','a'.repeat(40),'--format','json'],{encoding:'utf8',timeout:20000,env:{...process.env,PGHOST:'production.invalid',PGPORT:'1',PGDATABASE:'CANARY_DB',PGUSER:'CANARY_USER',PGPASSWORD:'CANARY_SECRET',PGOPTIONS:'-c role=tr_bootstrap'}});
 assert.equal(r.status,2,r.stderr);
 const report=JSON.parse(r.stdout);
 assert.deepEqual(report.summary,{pass:25,fail:0,inconclusive:1});
 assert.equal(report.provenance.adapters[1].fixture,'reviewed');
 assert.equal(new Set(report.results.map(r=>r.threat)).size,report.results.length);
 assert.doesNotMatch(r.stdout+r.stderr,/CANARY|production\.invalid|\/Users\/|\/tmp\/|synthetic-a/);
});
test('bounded subprocess timeout and output limits do not leak process output',async()=>{
 await assert.rejects(boundedProcess(process.execPath,['-e','setTimeout(()=>{},10000)'],{},50),/deadline/);
 await assert.rejects(boundedProcess(process.execPath,['-e',"process.stdout.write('x'.repeat(70000))"],{},2000),/output limit/);
});
