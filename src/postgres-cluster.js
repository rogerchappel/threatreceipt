import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

export async function postgresBinaries() {
  for (const dir of ['/opt/homebrew/opt/postgresql@16/bin', '/usr/lib/postgresql/16/bin']) {
    try {
      const resolved = await realpath(dir);
      const result = await boundedProcess(join(resolved, 'postgres'), ['--version'], {PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C'}, 3000);
      if (result.code === 0 && /^postgres \(PostgreSQL\) 16\./.test(result.stdout.trim())) return {dir:resolved,version:result.stdout.trim()};
    } catch { /* No PATH fallback: do not discover arbitrary executable names. */ }
  }
  throw new Error('PostgreSQL 16 is unavailable.');
}
/** Bounded subprocess with no shell, inherited credentials, or config environment. */
export function boundedProcess(executable, args, env, timeout = 5000, signal = undefined) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new Error('Cancelled.')); return; }
    const child = spawn(executable,args,{env,stdio:['ignore','pipe','pipe'],shell:false,detached:true});
    let stdout='',stderr='',problem;
    const stop = reason => { problem = reason; try { process.kill(-child.pid,'SIGKILL'); } catch {} };
    const timer=setTimeout(()=>stop('Process deadline exceeded.'),timeout);
    const abort=()=>stop('Cancelled.');
    signal?.addEventListener('abort',abort,{once:true});
    const collect = (kind, data) => {
      if (kind === 'stdout') stdout += data.toString(); else stderr += data.toString();
      if (Buffer.byteLength(stdout)+Buffer.byteLength(stderr)>65536) stop('Process output limit exceeded.');
    };
    child.stdout.on('data',d=>collect('stdout',d)); child.stderr.on('data',d=>collect('stderr',d));
    child.once('error',reject);
    child.once('close',code=>{
      clearTimeout(timer); signal?.removeEventListener('abort',abort);
      if (problem) reject(new Error(problem)); else resolve({code,stdout,stderr});
    });
  });
}
export async function startPostgres(options = {}) {
  const binaries=await postgresBinaries();
  // Use the real OS temp directory and one owned, unpredictable private root.
  const root=await mkdtemp(join(await realpath(tmpdir()),'tr-pg-'));
  const data=join(root,'data'),socket=join(root,'socket');
  const env={PATH:'/usr/bin:/bin',HOME:root,LANG:'C',LC_ALL:'C'};
  let server, closed=false, shutdownResult;
  const cleanup=async()=>{
    if (shutdownResult) return shutdownResult;
    let stopped=true;
    if (server && !closed) {
      server.kill('SIGINT');
      for(let i=0;i<60 && !closed;i++) await delay(50);
      if (!closed) { try { process.kill(-server.pid,'SIGKILL'); } catch {} for(let i=0;i<40 && !closed;i++) await delay(50); }
      stopped=closed;
    }
    if(server && closed) { try { process.kill(-server.pid,'SIGKILL'); } catch {} }
    let removed=false;
    if(stopped) { try { await rm(root,{recursive:true,force:true}); removed=true; } catch { /* preserve failed-cleanup status */ } }
    shutdownResult={stopped,removed}; return shutdownResult;
  };
  try {
    await mkdir(socket,{mode:0o700});
    const init=await boundedProcess(join(binaries.dir,'initdb'),['-D',data,'-U','tr_bootstrap','--auth-local=trust','--auth-host=reject','--no-locale','--encoding=UTF8'],env,15000,options.signal);
    if(init.code!==0) throw new Error('Initialization failed.');
    server=spawn(join(binaries.dir,'postgres'),['-D',data,'-c','listen_addresses=','-c',`unix_socket_directories=${socket}`,'-c','unix_socket_permissions=0700','-c','max_connections=10','-c','shared_buffers=16MB','-c','fsync=off','-p','5432'],{env,stdio:'ignore',shell:false,detached:true});
    server.once('exit',()=>{closed=true;});
    server.once('error',()=>{closed=true;});
    const sql=async(role,statement,timeout=5000)=>boundedProcess(join(binaries.dir,'psql'),['-X','-w','-q','-A','-t','--record-separator-zero','-h',socket,'-p','5432','-U',role,'-d','postgres','-v','ON_ERROR_STOP=1','-v','VERBOSITY=sqlstate','-c',statement],env,timeout,options.signal);
    let ready=false;
    for(let i=0;i<80;i++) {
      if(closed || options.signal?.aborted) break;
      const check=await boundedProcess(join(binaries.dir,'pg_isready'),['-h',socket,'-p','5432','-U','tr_bootstrap','-d','postgres'],env,1000,options.signal);
      if(check.code===0){ready=true;break;} await delay(50);
    }
    if(!ready) throw new Error('Startup failed.');
    return {sql,cleanup,version:binaries.version,
      // Internal lifecycle handle, used by acceptance tests; never manifest controlled.
      pid:server.pid,root};
  } catch {
    const result=await cleanup();
    const failure=new Error('PostgreSQL setup unavailable.');
    Object.assign(failure,{cleanup:result}); throw failure;
  }
}
