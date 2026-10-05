#!/usr/bin/env node
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { validateManifest } from '../src/manifest.js';
import { startFixture } from '../src/fixture.js';
import { runChecks, exitCode, toolVersion } from '../src/runner.js';
import { postgresInput } from '../src/postgres-input.js';
import { runPostgres } from '../src/postgres.js';
import { formatReport } from '../src/reports.js';
const usage = `ThreatReceipt ${toolVersion}
Usage: threatreceipt run MANIFEST [--fixture secure|vulnerable] [--format human|json|junit] [--execute]
Default: validate and plan only. --execute starts an owned synthetic loopback fixture.
Optional: --postgres secure|permissive|deny-all|reviewed
Reviewed policy SQL: --fixture-root DIR --reviewed-sql RELATIVE.sql --accept-reviewed-sql
Provenance: --application-commit FULL_HEX_REVISION (declared, not independently verified)
No existing database targets, credentials, shell commands or production probes are supported.
Exit codes: 0 complete pass, 1 failed invariant, 2 inconclusive, 64 invalid input.
`;
let fixture;
const cancellation = new AbortController();
const cancel = () => cancellation.abort();
process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
try {
  const args = process.argv.slice(2);
  if (args.length === 1 && ['--help', '--version'].includes(args[0])) {
    process.stdout.write(args[0] === '--version' ? toolVersion + '\n' : usage);
  } else {
    if (args[0] !== 'run' || !args[1] || args[1].startsWith('-')) throw new Error('usage');
    let profile = 'secure', format = 'human', execute = false, applicationCommit, postgresProfile, fixtureRoot, reviewedSQL, acceptSQL = false;
    const seen = new Set();
    for (let i = 2; i < args.length; i++) {
      const flag = args[i];
      if (seen.has(flag)) throw new Error('duplicate');
      seen.add(flag);
      if (flag === '--execute') execute = true;
      else if (flag === '--fixture') profile = args[++i];
      else if (flag === '--format') format = args[++i];
      else if (flag === '--application-commit') applicationCommit = args[++i];
      else if (flag === '--postgres') postgresProfile = args[++i];
      else if (flag === '--fixture-root') fixtureRoot = args[++i];
      else if (flag === '--reviewed-sql') reviewedSQL = args[++i];
      else if (flag === '--accept-reviewed-sql') acceptSQL = true;
      else throw new Error('unknown');
    }
    if (!['secure', 'vulnerable'].includes(profile) || !['human', 'json', 'junit'].includes(format)) throw new Error('option');
    if (seen.has('--application-commit') && (typeof applicationCommit !== 'string' || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(applicationCommit))) throw new Error('revision');
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
    if ((seen.has('--fixture-root') && !fixtureRoot) || (seen.has('--reviewed-sql') && !reviewedSQL)) throw new Error('missing sql option');
    if (seen.has('--postgres') && !postgresProfile) throw new Error('postgres');
    if (!postgresProfile && (fixtureRoot || reviewedSQL || acceptSQL || seen.has('--fixture-root') || seen.has('--reviewed-sql'))) throw new Error('sql options');
    if (postgresProfile && !manifest.threats.some(t => t.check === 'postgres-rls')) throw new Error('missing postgres threat');
    const pgInput = postgresProfile ? await postgresInput(postgresProfile, fixtureRoot, reviewedSQL, acceptSQL) : undefined;
    if (execute) fixture = await startFixture(profile);
    const postgresReport = execute && pgInput ? await runPostgres(pgInput, {signal:cancellation.signal}) : undefined;
    const postgresPlanned = pgInput ? {name:'postgres-rls',fixture:pgInput.profile,fixtureSha256:pgInput.sha256,runtime:'not-executed'} : undefined;
    const report = await runChecks(manifest, fixture?.origin, execute, {httpFixture: profile, applicationCommit, postgresReport, postgresPlanned});
    process.stdout.write(formatReport(report, format));
    process.exitCode = exitCode(report);
  }
} catch {
  // Never echo input, paths, secrets, bodies, stack traces or transport errors.
  process.stderr.write('Invalid input or unavailable local fixture. See --help and the manifest schema.\n');
  process.exitCode = 64;
} finally {
  if (fixture) await fixture.close();
  process.off('SIGINT', cancel); process.off('SIGTERM', cancel);
}
