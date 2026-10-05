import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
const temporary = mkdtempSync(join(tmpdir(), 'threatreceipt-package-'));
const run = (cmd,args,cwd) => {
  const r = spawnSync(cmd,args,{cwd,encoding:'utf8',timeout:30000});
  assert.equal(r.status,0,r.stderr || r.stdout); return r.stdout;
};
try {
  const packed = JSON.parse(run('npm',['pack','--ignore-scripts','--json','--pack-destination',temporary],process.cwd()))[0];
  for (const f of packed.files) assert.ok(!/node_modules|\.env|\.git\/|reports\//.test(f.path),f.path);
  run('tar',['-xzf',join(temporary,packed.filename),'-C',temporary],process.cwd());
  const cwd = join(temporary,'package');
  assert.equal(run(process.execPath,['bin/threatreceipt.js','--version'],cwd).trim(),JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8')).version);
  const r = spawnSync(process.execPath,['bin/threatreceipt.js','run','examples/shortlist.json','--format','json'],{cwd,encoding:'utf8'});
  assert.equal(r.status,2); assert.equal(JSON.parse(r.stdout).summary.inconclusive,6);
  console.log('Packed CLI smoke passed; runtime needs no installed dependencies.');
} finally { rmSync(temporary,{recursive:true,force:true}); }
