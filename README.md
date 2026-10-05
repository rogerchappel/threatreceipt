# ThreatReceipt

Feature → threat → invariant → test → fix → evidence.

A small, deterministic security test kit and teaching CLI for the ShipMode community. Version 0.2 runs **real HTTP requests against an owned synthetic loopback fixture**, mapping each result to an explicit threat. No LLM, API keys, cloud graders or runtime dependencies.

**This version does not test your application.** Its HTTP checks use a bundled two-tenant read-only API; its database adapter can exercise a reviewed policy adapted to a narrow synthetic table contract. An optional adapter runs actual PostgreSQL RLS assertions in a disposable cluster, including an opt-in reviewed-policy fixture. Agent prompt-injection coverage remains inconclusive. It is not a penetration tester, SQL injection scanner, or security certification.

## Quickstart

Requires Node.js 22 or newer and Git. No dependency install is needed to run the CLI.

```sh
git clone https://github.com/rogerchappel/threatreceipt.git
cd threatreceipt
node bin/threatreceipt.js --help
node bin/threatreceipt.js run examples/shortlist.json
```

The default is a dry run and returns **2** (inconclusive). It validates the manifest without opening a server or making requests.

```sh
node bin/threatreceipt.js run examples/shortlist.json --fixture vulnerable --execute
node bin/threatreceipt.js run examples/shortlist.json --fixture secure --execute
```

| Mode | HTTP pass | HTTP fail | Unverified | Exit |
| --- | ---: | ---: | ---: | ---: |
| Dry run | 0 | 0 | 6 | 2 |
| Vulnerable | 1 | 3 | 2 | 1 |
| Secure | 4 | 0 | 2 | 2 |

The secure fixture still exits 2: its four HTTP checks pass, but database and agent coverage remains missing unless the PostgreSQL adapter is selected (agent coverage still remains missing). Code 0 is reserved for complete coverage; the current version never claims it. Do not use `|| true` to turn this result into a security gate success.

## What is tested

- Positive owner access: expected record and synthetic content must be present.
- Cross-tenant denial: both 403 and a body without leaked records.
- Anonymous denial: both 401 and a body without leaked records.
- Literal handling of one hostile lookup key: 404 instead of a broadened lookup. This is an input-boundary regression, **not proof against SQL or code injection**; the fixture has no SQL engine.

The intentionally vulnerable profile ignores identity, ownership and lookup filtering. The secure profile implements each corresponding guard in [src/fixture.js](src/fixture.js). Demo identity headers are not production authentication.

## Actual PostgreSQL policy tests

```sh
node bin/threatreceipt.js run examples/shortlist.json --postgres secure --execute
```

Requires existing PostgreSQL 16 binaries. Expected: 25 passes and one inconclusive agent check, exit 2. The runner owns the temporary cluster and never uses existing databases or production credentials. [Database adapter instructions](docs/postgres.md) cover both-tenant CRUD, mutation controls, trusted reviewed SQL, cleanup and the exact application-integration limits.

## Evidence and automation

```sh
mkdir -p reports
node bin/threatreceipt.js run examples/shortlist.json --execute --format json > reports/secure.json
node bin/threatreceipt.js run examples/shortlist.json --execute --format junit > reports/secure.xml
```

These commands return 2 as documented. Receipt schema version 2 includes tool version, canonical-manifest SHA-256, adapter source digests, selected fixture identity, fixed invariants and outcomes. PostgreSQL receipts also include the executed SQL digest and runtime version. An optional application revision is explicitly marked as a user-declared reference. Raw bodies, request headers, target ports, machine paths and error stacks are excluded. Feature and threat labels are included: never put secrets in labels. JUnit represents inconclusive coverage as skipped; consumers must inspect skipped counts and the CLI exit code.

See [manifest reference](docs/manifest.md), [course exercise](docs/lesson.md), [agent skill](SKILL.md), and [adapter research](docs/adapters.md).

## Development and packaging

```sh
npm ci --ignore-scripts
npm run release:check
npm pack --ignore-scripts
```

Pinned development dependencies supply TypeScript checking of JavaScript; there are no runtime dependencies. `build` checks syntax because the source is directly executable. The package smoke test extracts the tarball and runs its CLI without installing dependencies. [Release instructions](docs/releasing.md) describe the readiness workflow. No npm release or GitHub release is required for source usage.

## Provenance and license

MIT, copyright Roger Chappel. Packaging and review conventions were adapted from [Stackforge](https://github.com/rogerchappel/stackforge/tree/fa5c5fce93567b802b5a96224cc4b6f228930b52): CLI bin, explicit package file list, release checks and package smoke. Product source and course material are original. CI uses pinned actions and read-only repository permissions; it does not clone or run ReleaseBox. No scanner engine or third-party rule pack is bundled.
