#!/usr/bin/env node
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { validateManifest } from '../src/manifest.js';
import { startFixture } from '../src/fixture.js';
import { runChecks, exitCode } from '../src/runner.js';
import { formatReport } from '../src/reports.js';
const usage = `ThreatReceipt 0.1.0
Usage: threatreceipt run MANIFEST [--fixture secure|vulnerable] [--format human|json|junit] [--execute]
Default: validate and plan only. --execute starts an owned synthetic loopback fixture.
No arbitrary targets, credentials, scripts or production probes are supported.
Exit codes: 0 complete pass, 1 failed invariant, 2 inconclusive, 64 invalid input.
`;
let fixture;
try {
  const args = process.argv.slice(2);
  if (args.length === 1 && ['--help', '--version'].includes(args[0])) {
    process.stdout.write(args[0] === '--version' ? '0.1.0\n' : usage);
  } else {
    if (args[0] !== 'run' || !args[1] || args[1].startsWith('-')) throw new Error('usage');
    let profile = 'secure', format = 'human', execute = false;
    const seen = new Set();
    for (let i = 2; i < args.length; i++) {
      const flag = args[i];
      if (seen.has(flag)) throw new Error('duplicate');
      seen.add(flag);
      if (flag === '--execute') execute = true;
      else if (flag === '--fixture') profile = args[++i];
      else if (flag === '--format') format = args[++i];
      else throw new Error('unknown');
    }
    if (!['secure', 'vulnerable'].includes(profile) || !['human', 'json', 'junit'].includes(format)) throw new Error('option');
    const file = await open(args[1], constants.O_RDONLY | constants.O_NONBLOCK);
    let manifest;
    try {
      const stat = await file.stat();
      if (!stat.isFile() || stat.size > 16384) throw new Error('size');
      const bytes = Buffer.alloc(16385);
      const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
      if (bytesRead > 16384) throw new Error('size');
      manifest = validateManifest(JSON.parse(bytes.subarray(0, bytesRead).toString('utf8')));
    } finally { await file.close(); }
    if (execute) fixture = await startFixture(profile);
    const report = await runChecks(manifest, fixture?.origin, execute);
    process.stdout.write(formatReport(report, format));
    process.exitCode = exitCode(report);
  }
} catch {
  // Never echo input, paths, secrets, bodies, stack traces or transport errors.
  process.stderr.write('Invalid input or unavailable local fixture. See --help and the manifest schema.\n');
  process.exitCode = 64;
} finally {
  if (fixture) await fixture.close();
}
