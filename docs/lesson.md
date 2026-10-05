# ShipMode lesson: test the rule you meant

Allow 20–30 minutes. Prerequisites: Node.js 22+, a checkout of this repository, basic terminal familiarity. Everything uses synthetic data on your own computer. No account, API key, database or paid service is required.

## 1. Write the threat model

Feature: read a team's saved shortlist. Asset: a tenant's private record. Actors: owner, another tenant, anonymous caller. Trust boundary: client-supplied identity and record key crossing into the server.

Write two sentences before running anything: what must the owner be able to do, and what must other actors never see? Review [the manifest](../examples/shortlist.json). Threat IDs link these rules to executable checks; a language-model score cannot replace those rules.

## 2. Observe failure

```sh
node bin/threatreceipt.js run examples/shortlist.json --fixture vulnerable --execute
```

Expected: one pass, three failures, two inconclusive results; exit 1. Explain why owner access alone proves nothing about isolation. Read the vulnerable path in `src/fixture.js`. It ignores caller identity and returns the record for any key.

## 3. Inspect the fix and rerun

```sh
node bin/threatreceipt.js run examples/shortlist.json --fixture secure --execute
```

Expected: four HTTP passes, no HTTP failures, two inconclusive results; exit 2. Compare the secure guards in `src/fixture.js` with each invariant. The same manifest ran both times; the implementation changed, not the expected result.

## 4. Make a regression

On a local exercise branch, remove only the secure tenant comparison in `src/fixture.js`. Predict the failing check, rerun the secure command, then restore that line. Keep the positive owner check: denying everybody is not a fix. Run `npm ci --ignore-scripts` followed by `npm run release:check` after restoring the guard.

## 5. Save evidence

```sh
mkdir -p reports
node bin/threatreceipt.js run examples/shortlist.json --execute --format json > reports/secure.json
```

Expected exit 2. Submit your two threat-model sentences, a vulnerable report, a fixed report, and three protections that remain untested. Example gaps: actual PostgreSQL role/JWT context, write permissions and agent tool actions. Reports are ignored by Git by default; share only reviewed synthetic evidence.

## Acceptance rubric

- Explains the owner-positive and cross-tenant-negative cases.
- Demonstrates the vulnerable implementation failing and the secure implementation passing HTTP checks with unchanged expectations.
- Does not describe the fixture as testing a real application or proving SQL injection resistance.
- Preserves and explains inconclusive database/agent coverage.
- Proposes the next invariant for a real feature and identifies the adapter/fixture needed to test it.

## Agent-assisted exercise

Load the repository's [SKILL.md](../SKILL.md) into an agent with repository access, or ask the agent to read it. Ask: “Model the read-shortlist feature, run both local demo profiles, and explain what the evidence does and does not verify.” This file accompanies the whole repository; copying the skill alone does not install the CLI. No Skool site changes are needed to use this lesson.

## Optional extension: prove a bundled database policy

With PostgreSQL 16.15+ already available, follow [the database exercise](postgres.md). Run secure, permissive and deny-all policies and compare the same CRUD expectations. Explain why these fixtures do not verify your application schema or JWT validation. External SQL execution is disabled; do not use commands from earlier draft revisions to import a policy.
