import { constants } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import { resolve, relative, isAbsolute, join } from 'node:path';
import { createHash } from 'node:crypto';

export const builtInSQL = profile => `
GRANT SELECT, INSERT, UPDATE, DELETE ON fixture.records TO tr_tenant_a, tr_tenant_b;
ALTER TABLE fixture.records ENABLE ROW LEVEL SECURITY;
${profile === 'deny-all' ? '' : `CREATE POLICY tenant_access ON fixture.records TO tr_tenant_a, tr_tenant_b USING (${profile === 'permissive' ? 'true' : "tenant_id = current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id'"}) WITH CHECK (${profile === 'permissive' ? 'true' : "tenant_id = current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id'"});`}
`;
/** Read a bounded, explicitly reviewed SQL file; no symlinks or external paths. */
export async function postgresInput(profile, root, sqlFile, accept) {
  let sql;
  if (['secure','permissive','deny-all'].includes(profile)) {
    if(root || sqlFile || accept) throw new Error('Unexpected reviewed input.');
    sql=builtInSQL(profile);
  } else if(profile === 'reviewed') {
    if(!accept || !root || !sqlFile || isAbsolute(sqlFile) || sqlFile.split(/[\\/]/).some(p=>p==='..' || p==='')) throw new Error('Reviewed SQL opt-in required.');
    const lexicalRoot=resolve(root), actualRoot=await realpath(lexicalRoot);
    if(actualRoot !== lexicalRoot || !(await lstat(actualRoot)).isDirectory()) throw new Error('Symlink fixture root rejected.');
    let cursor=actualRoot;
    for(const segment of sqlFile.split(/[\\/]/)) {
      cursor=join(cursor,segment); if((await lstat(cursor)).isSymbolicLink()) throw new Error('Symlink SQL rejected.');
    }
    const target=resolve(actualRoot,sqlFile),rel=relative(actualRoot,target);
    if(!rel || rel.startsWith('..') || isAbsolute(rel)) throw new Error('External SQL rejected.');
    const file=await open(target,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    try {
      const stat=await file.stat(); if(!stat.isFile() || stat.size>32768) throw new Error('Invalid SQL file.');
      const buffer=Buffer.alloc(32769); const {bytesRead}=await file.read(buffer,0,buffer.length,0);
      if(bytesRead>32768) throw new Error('SQL too large.');
      sql=new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,bytesRead));
    } finally {await file.close();}
    if(!sql.trim() || sql.includes('\0')) throw new Error('Invalid SQL.');
  } else throw new Error('Unknown PostgreSQL fixture.');
  return {profile,sql,sha256:createHash('sha256').update(sql).digest('hex')};
}
