# Bundled PostgreSQL RLS checks

The optional adapter tests actual PostgreSQL policies using only the bundled synthetic fixtures. It creates a new private temporary cluster, runs assertions as restricted tenant logins, rolls back each case, stops the process and removes its files. It never connects to an existing database.

**Reviewed or external SQL execution is disabled.** Its privilege boundary is not approved for use. Do not use earlier draft revisions that accepted external SQL. Application-schema integration remains future work requiring independent security validation.

## Patched runtime requirement

PostgreSQL **16.15 or newer in the 16.x series** is required for `postgres`, `psql`, `initdb` and `pg_isready`. The runner checks existing standard Homebrew and Debian binary locations without installing or upgrading software. It records the selected server version in the receipt.

This floor was checked against the [official PostgreSQL 16 security advisories](https://www.postgresql.org/support/security/16/) on 2026-10-05. Version 16.15 includes core-server code-execution fixes absent from 16.13. Keep tooling on the latest supported security patch; the minimum is not a promise against future advisories.

Existing installations are never upgraded by the runner. Version 16.13 now produces inconclusive database coverage. CI uses an official 16.15 image pinned by digest, with networking disabled, a non-root user, read-only source and temporary writable storage.

```sh
node bin/threatreceipt.js run examples/shortlist.json --postgres secure
node bin/threatreceipt.js run examples/shortlist.json --postgres secure --execute
node bin/threatreceipt.js run examples/shortlist.json --postgres permissive --execute
node bin/threatreceipt.js run examples/shortlist.json --postgres deny-all --execute
```

The first command validates and plans without starting a database. With supported tooling, the secure command reports 25 passes (four HTTP checks, 20 database assertions and cleanup), no failures and one inconclusive agent check; exit 2. Mutation controls expose failures; exit 1. Missing or outdated tooling stays inconclusive and must never be treated as complete security approval.

## Database assertions and limits

For each of two tenants, check allowed and forbidden SELECT, INSERT, UPDATE and DELETE, plus forbidden tenant reassignment. Returned rows and in-transaction table fingerprints must match the expected synthetic state. A second observer checks the original data after rollback.

Tenant connections verify their actual login/session role, non-superuser status, absence of BYPASSRLS, non-ownership and no membership in the fixture-owner role. The test harness supplies synthetic JWT claims. It does not verify JWT signatures, HTTP authentication, real application routes, deployed migrations, anonymous roles, concurrency or other tables.

The observer is a separate non-superuser with BYPASSRLS and SELECT access to the synthetic table. Its snapshot function is runner-owned. Bootstrap login is disabled before bundled policies are loaded. Catalog-only checks reject executable or structural fixture changes before post-load table reads. These are defensive controls for bundled fixtures, not approval to execute arbitrary SQL. Source inputs must exactly match a bundled profile; CLI options from the former reviewed-SQL interface fail rather than silently falling back.

## Lifecycle and evidence

TCP is disabled. The socket directory is private, and database environment/configuration is not inherited. New-cluster socket authentication requires no password and affects only this disposable cluster. Existing services, credentials and security settings remain untouched.

Execution and output are bounded. Unreached assertions, startup failures, cancellation, server crashes and unconfirmed cleanup remain inconclusive. SIGINT/SIGTERM initiate cleanup. Machine crashes or SIGKILL of the CLI cannot run JavaScript cleanup, so an absent receipt cannot establish cleanup.

Receipts include the exact bundled SQL digest, adapter digest, required minimum and actual runtime. Optional application revisions are user-declared references only; the runner neither loads nor verifies those application sources.

Run `THREATRECEIPT_REQUIRE_POSTGRES=1 node --test test/postgres.test.js` to require patched PostgreSQL. Without that flag, database tests skip when compatible tooling is absent. The dedicated CI job requires the patched runtime and cannot pass by skipping database tests.
