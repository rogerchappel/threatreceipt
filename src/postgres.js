import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { builtInSQL } from './postgres-input.js';
import { startPostgres, MINIMUM_POSTGRES } from './postgres-cluster.js';
const sourceSha256=createHash('sha256').update(readFileSync(new URL('./postgres.js',import.meta.url))).update(readFileSync(new URL('./postgres-cluster.js',import.meta.url))).update(readFileSync(new URL('./postgres-input.js',import.meta.url))).digest('hex');
const bootstrap=`
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON DATABASE postgres FROM PUBLIC;
CREATE ROLE tr_observer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
CREATE ROLE tr_fixture_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE tr_tenant_a LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE tr_tenant_b LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE SCHEMA fixture AUTHORIZATION tr_fixture_owner;
GRANT USAGE ON SCHEMA fixture TO tr_tenant_a,tr_tenant_b,tr_observer;
`;
const parse = result => {
  if(result.code!==0) throw new Error('SQL failed.');
  return result.stdout.split('\0').map(s=>s.trim()).filter(Boolean).map(line=>JSON.parse(line));
};
const snapshot=`SELECT tr_receipt_audit.snapshot() AS fingerprint`;
const auditSQL=`
GRANT SELECT ON fixture.records TO tr_observer;
CREATE SCHEMA tr_receipt_audit;
GRANT USAGE ON SCHEMA tr_receipt_audit TO tr_observer;
REVOKE ALL ON SCHEMA tr_receipt_audit FROM PUBLIC;
GRANT USAGE ON SCHEMA tr_receipt_audit TO tr_tenant_a,tr_tenant_b;
CREATE FUNCTION tr_receipt_audit.snapshot() RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $body$
 SELECT encode(sha256(convert_to(COALESCE(string_agg(row_to_json(t)::text, ',' ORDER BY t.id), ''),'UTF8')),'hex') FROM fixture.records t;
$body$;
ALTER FUNCTION tr_receipt_audit.snapshot() OWNER TO tr_observer;
REVOKE ALL ON FUNCTION tr_receipt_audit.snapshot() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tr_receipt_audit.snapshot() TO tr_tenant_a,tr_tenant_b;
ALTER ROLE tr_bootstrap NOLOGIN;
`;

// Catalog-only inspection. No fixture relation scans or expression deparsing.
// Defense in depth for bundled policies. External SQL execution is disabled.
export async function fixtureBoundary(cluster) {
  return parse(await cluster.sql('tr_observer',`SET search_path=pg_catalog;
    SELECT json_build_object(
      'oid',c.oid::text,'owner',c.relowner::text,'kind',c.relkind,'rowtype',c.reltype::text,'accessMethod',c.relam,
      'columns',(SELECT json_agg(json_build_object('name',a.attname,'type',a.atttypid,'modifier',a.atttypmod,'notNull',a.attnotnull,'generated',a.attgenerated,'default',a.atthasdef,'dropped',a.attisdropped) ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0),
      'indexes',(SELECT json_agg(json_build_object('oid',i.indexrelid::text,'expressions',i.indexprs IS NOT NULL,'predicate',i.indpred IS NOT NULL,'classes',i.indclass::text) ORDER BY i.indexrelid) FROM pg_index i WHERE i.indrelid=c.oid),
      'constraints',(SELECT json_agg(k.oid::text ORDER BY k.oid) FROM pg_constraint k WHERE k.conrelid=c.oid),
      'functions',(SELECT count(*) FROM pg_proc p WHERE p.proowner=(SELECT oid FROM pg_roles WHERE rolname='tr_fixture_owner')),
      'triggers',(SELECT count(*) FROM pg_trigger t WHERE t.tgrelid=c.oid),
      'rules',(SELECT count(*) FROM pg_rewrite r WHERE r.ev_class=c.oid),
      'statistics',(SELECT count(*) FROM pg_statistic_ext s WHERE s.stxrelid=c.oid),
      'inheritance',(SELECT count(*) FROM pg_inherits h WHERE h.inhrelid=c.oid OR h.inhparent=c.oid)
    ) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='fixture' AND c.relname='records';`))[0];
}

const columns='id,tenant_id,value';
const rowset=sql=>`SELECT json_build_object('rows',COALESCE(json_agg(q ORDER BY q.id),'[]'::json)) FROM (${sql}) q`;
const mutation=sql=>`WITH changed AS (${sql} RETURNING ${columns}) SELECT json_build_object('rows',COALESCE(json_agg(changed ORDER BY id),'[]'::json)) FROM changed`;
const seeded=[{id:1,tenant_id:'tenant-a',value:'synthetic-a'},{id:2,tenant_id:'tenant-b',value:'synthetic-b'}];
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const fingerprint=rows=>createHash('sha256').update([...rows].sort((a,b)=>a.id-b.id).map(r=>JSON.stringify(r)).join(',')).digest('hex');
export async function tenantRoleSafe(cluster, role) {
  const identity=parse(await cluster.sql(role,`SELECT json_build_object('current',current_user,'session',session_user,'super',r.rolsuper,'bypass',r.rolbypassrls,'ownerMember',pg_has_role(current_user,'tr_fixture_owner','MEMBER'),'owner',pg_get_userbyid(c.relowner)) FROM pg_roles r CROSS JOIN pg_class c WHERE r.rolname=current_user AND c.oid='fixture.records'::regclass;`))[0];
      const valid=identity?.current===role && identity?.session===role && identity?.super===false && identity?.bypass===false && identity?.ownerMember===false && identity?.owner!==role;
  return valid;
}
export async function runPostgres(input, options = {}) {
  const checks=[];
  const planned=['a','b'].flatMap(actor=>[`${actor}-role-context`,...['allow','deny'].flatMap(permission=>['select','insert','update','delete'].map(op=>`${actor}-${permission}-${op}`)),`${actor}-deny-reassignment`]);
  const provenance={name:'postgres-rls',fixture:input.profile,fixtureSha256:createHash('sha256').update(input.sql).digest('hex'),sourceSha256,runtime:'unavailable',minimumRuntime:MINIMUM_POSTGRES,transport:'owned-private-unix-socket'};
  let stage='bundled-input',cluster,cleanup={stopped:true,removed:true};
  const add=(id,status,evidence)=>checks.push({id,status,evidence});
  try {
    if(!['secure','permissive','deny-all'].includes(input.profile) || input.sql!==builtInSQL(input.profile)) throw new Error('External SQL disabled.');
    stage='cluster';
    cluster=await startPostgres({signal:options.signal}); provenance.runtime=cluster.version;
    stage='bootstrap';
    if((await cluster.sql('tr_bootstrap',bootstrap)).code!==0) throw new Error('Setup failed.');
    // Seed before reviewed code exists: never invoke user-defined triggers as bootstrap.
    if((await cluster.sql('tr_fixture_owner',"CREATE TABLE fixture.records (id integer PRIMARY KEY, tenant_id text NOT NULL, value text NOT NULL); INSERT INTO fixture.records VALUES (1,'tenant-a','synthetic-a'),(2,'tenant-b','synthetic-b');")).code!==0) throw new Error('Seed failed.');
    // Create the trusted snapshot before fixture code exists, then permanently disable bootstrap login.
    stage='observer-setup';
    if((await cluster.sql('tr_bootstrap',auditSQL)).code!==0) throw new Error('Observer setup failed.');
    const originalBoundary=await fixtureBoundary(cluster);
    if(!originalBoundary) throw new Error('Fixture metadata unavailable.');
    // One -c argument starting with BEGIN is sent as SQL, never interpreted as psql meta-commands.
    stage='bundled-sql';
    const loaded=await cluster.sql('tr_fixture_owner',`BEGIN; SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'; ${input.sql}\n; COMMIT;`,5000);
    if(loaded.code!==0) throw new Error('Bundled SQL failed.');
    stage='fixture-capabilities';
    if(!same(await fixtureBoundary(cluster),originalBoundary)) throw new Error('Unsupported fixture capabilities.');
    stage='seed-contract';
    const seed=await cluster.sql('tr_observer',rowset(`SELECT ${columns} FROM fixture.records`));
    if(!same(parse(seed)[0]?.rows,seeded)) throw new Error('Fixture seed contract failed.');
    stage='role-and-access-checks';
    for(const actor of ['a','b']) {
      const role=`tr_tenant_${actor}`;
      const valid=await tenantRoleSafe(cluster,role);
      add(`${actor}-role-context`,valid?'pass':'fail',valid?'Direct tenant login is non-owner, non-superuser and non-BYPASSRLS.':'Unsafe tenant role context; access assertions not executed.');
      if(!valid) throw new Error('Unsafe role.');
    }
    stage='role-and-access-checks';
    for(const actor of ['a','b']) {
      const own=actor==='a'?seeded[0]:seeded[1],other=actor==='a'?seeded[1]:seeded[0];
      const role=`tr_tenant_${actor}`;
      const prefix=`BEGIN; SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'; SET LOCAL request.jwt.claims='${JSON.stringify({sub:actor==='a'?'00000000-0000-0000-0000-000000000001':'00000000-0000-0000-0000-000000000002',tenant_id:own.tenant_id})}'; SELECT json_build_object('fingerprint',(${snapshot}));`;
      for(const permission of ['allow','deny']) for(const operation of ['select','insert','update','delete']) {
        const target=permission==='allow'?own:other;
        let query,expected;
        if(operation==='select') {query=rowset(`SELECT ${columns} FROM fixture.records WHERE id=${target.id}`);expected=permission==='allow'?[target]:[];}
        else if(operation==='insert') {query=mutation(`INSERT INTO fixture.records VALUES (101,'${target.tenant_id}','new-value')`);expected=[{id:101,tenant_id:target.tenant_id,value:'new-value'}];}
        else if(operation==='update') {query=mutation(`UPDATE fixture.records SET value='updated' WHERE id=${target.id}`);expected=permission==='allow'?[{...target,value:'updated'}]:[];}
        else {query=mutation(`DELETE FROM fixture.records WHERE id=${target.id}`);expected=permission==='allow'?[target]:[];}
        const id=`${actor}-${permission}-${operation}`;
        const result=await cluster.sql(role,`${prefix} ${query}; SELECT json_build_object('fingerprint',(${snapshot})); ROLLBACK;`);
        if(result.code===2 || /(?:ERROR|FATAL):\s+(?:57|08)/.test(result.stderr)) {
          add(id,'inconclusive','Database connection or statement interrupted; operation unverified.');
          throw new Error('Database interrupted.');
        }
        if(permission==='deny' && operation==='insert') {
          const denied=result.code>0 && /ERROR:\s+42501\b/.test(result.stderr);
          add(id,denied?'pass':'fail',denied?'Foreign-tenant insert rejected with SQLSTATE 42501; connection transaction rolled back.':'Expected foreign-tenant insert rejection was not observed.');
        } else if(result.code!==0) {
          add(id,'fail','Expected operation result unavailable; SQL permission or policy behavior mismatched.');
        } else {
          const outputs=parse(result);const returned=outputs[1]?.rows;
          let expectedState=seeded;
          if(permission==='allow' && operation==='insert') expectedState=[...seeded,...expected];
          if(permission==='allow' && operation==='update') expectedState=seeded.map(r=>r.id===target.id?expected[0]:r);
          if(permission==='allow' && operation==='delete') expectedState=seeded.filter(r=>r.id!==target.id);
          const unaffected=outputs[0]?.fingerprint===fingerprint(seeded) && outputs[2]?.fingerprint===fingerprint(expectedState);
          const valid=same(returned,expected)&&unaffected;
          add(id,valid?'pass':'fail',`Expected ${expected.length} returned row(s); ${Array.isArray(returned)?returned.length:'invalid'} observed; ${unaffected?'complete fixture state matched':'unexpected fixture state or side effects'}.`);
        }
        // Restricted observer checks persistence after each rolled-back tenant connection.
        const after=parse(await cluster.sql('tr_observer',rowset(`SELECT ${columns} FROM fixture.records`)))[0];
        if(!same(after?.rows,seeded)) {add(`${id}-rollback`,'fail','Fixture changed after transaction rollback.');throw new Error('Rollback failed.');}
      }
      const reassigned=await cluster.sql(role,`${prefix} ${mutation(`UPDATE fixture.records SET tenant_id='${other.tenant_id}' WHERE id=${own.id}`)}; ROLLBACK;`);
      const blocked=reassigned.code>0 && /ERROR:\s+42501\b/.test(reassigned.stderr);
      add(`${actor}-deny-reassignment`,blocked?'pass':'fail',blocked?'Tenant reassignment rejected with SQLSTATE 42501.':'Expected tenant reassignment rejection was not observed.');
      const after=parse(await cluster.sql('tr_observer',rowset(`SELECT ${columns} FROM fixture.records`)))[0];
      if(!same(after?.rows,seeded)) throw new Error('Reassignment rollback failed.');
    }
  } catch (error) {
    if(error.cleanup) cleanup=error.cleanup;
    add('execution','inconclusive',`PostgreSQL ${stage} unavailable; remaining coverage unverified.`);
  } finally {
    if(cluster) cleanup=await cluster.cleanup();
    for(const id of planned) if(!checks.some(c=>c.id===id)) add(id,'inconclusive','Assertion not reached; protection unverified.');
    add('cleanup',cleanup.stopped&&cleanup.removed?'pass':'inconclusive',cleanup.stopped&&cleanup.removed?'No owned PostgreSQL resources remain.':'Owned process or temporary cluster cleanup could not be confirmed.');
  }
  return {checks,provenance,cleanup};
}
