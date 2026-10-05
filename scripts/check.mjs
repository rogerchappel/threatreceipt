import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
for (const dir of ['src', 'bin', 'scripts', 'test']) {
  for (const file of readdirSync(dir).filter(f => /\.m?js$/.test(f))) {
    const r = spawnSync(process.execPath, ['--check', `${dir}/${file}`], {stdio:'inherit'});
    if (r.status !== 0) process.exit(1);
  }
}
console.log('JavaScript syntax checks passed (no transpilation required).');
