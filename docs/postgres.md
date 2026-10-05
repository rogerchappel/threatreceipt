# Real PostgreSQL RLS checks

The optional PostgreSQL adapter tests actual PostgreSQL policies and grants. It starts a new temporary PostgreSQL 16 cluster for every execution, creates synthetic data, runs assertions as restricted tenant logins, rolls back each case, stops the process and removes the cluster. It never connects to an existing database.

## Requirements and first run

Use an already installed PostgreSQL 16 distribution in either the standard Homebrew or Debian binary directory. The runner discovers only those locations, verifies the major version and records the exact runtime version in its receipt. It does not install anything or search arbitrary executables through PATH. Local verification used PostgreSQL 16.13. Missing tooling produces inconclusive coverage.

```sh
node bin/threatreceipt.js run examples/shortlist.json --postgres secure
node bin/threatreceipt.js run examples/shortlist.json --postgres secure --execute
node bin/threatreceipt.js run examples/shortlist.json --postgres permissive --execute
node bin/threatreceipt.js run examples/shortlist.json --postgres deny-all --execute
```

The first command only validates and plans. The secure command reports 25 passes (four HTTP checks, 20 PostgreSQL assertions and one cleanup check), no failures and one inconclusive agent check; exit 2. Both mutation controls expose failures; exit 1. A nonzero exit is intentional and must not be converted into a complete security approval.

## Asserted database behavior

For each of two tenants, check allowed and forbidden SELECT, INSERT, UPDATE and DELETE, plus forbidden tenant reassignment. SELECT and data-changing statements return exact expected rows. A runner-owned observer hashes the entire fixture table before and after successful statements inside the transaction, catching foreign-row changes caused by triggers as well as direct writes. A second observer verifies the original data after rollback.

Tests connect directly as `tr_tenant_a` and `tr_tenant_b`. Before assertions they verify `current_user`, `session_user`, non-superuser status, no BYPASSRLS, non-ownership and no membership in the owner role. Each tenant session receives synthetic `request.jwt.claims` with a distinct `sub` UUID and `tenant_id`. The harness sets these claims as test inputs: it **does not verify JWT signatures, token issuance, HTTP authentication or resistance to forged claims** in an application.

The fixture owner is `tr_fixture_owner`, also a non-superuser without BYPASSRLS or role/database-creation privileges. A separate bootstrap role creates the isolated test environment and observes results; it never runs the access assertions or executes supplied SQL. Synthetic records are seeded before reviewed SQL is loaded, so supplied triggers are not invoked by privileged seed writes.

## Adapt a reviewed application policy

The first integration contract is deliberately narrow: a pre-seeded ordinary table named `fixture.records`, with exactly `id integer`, `tenant_id text`, `value text`. Adapt a policy from your application's reviewed migration to this contract in a local SQL file. Review any changed identifiers or helper functions and record the original migration commit. Never use a private application schema without authorization.

```sh
node bin/threatreceipt.js run examples/shortlist.json \
  --postgres reviewed \
  --fixture-root "$PWD" \
  --reviewed-sql examples/postgres/reviewed-policy.sql \
  --accept-reviewed-sql \
  --execute --format json
```

Optionally add `--application-commit` followed by the full 40- or 64-character lowercase hexadecimal revision of the reviewed source. This is a **user-declared reference**, not independently verified source provenance. The receipt separately hashes the actual loaded SQL and adapter source.

The SQL file must be inside an explicit canonical fixture root, with a relative path, no symlinks or parent traversal, valid UTF-8 and at most 32 KiB. The runner-owned table and seed rows must remain intact after loading. The example grants CRUD and creates a tenant claim policy. You can edit those policy and grant statements to reproduce your reviewed application's rule; unrelated schema shapes are unsupported.

**SQL is trusted code, not passive configuration.** The flag acknowledges that review. It is sent as one server-side SQL command under the restricted fixture-owner login, not as a psql script; psql shell commands, superuser escalation and `COPY PROGRAM` are tested as rejected. There is no URL, password, remote database, arbitrary shell or plugin field. These restrictions do not make arbitrary SQL safe against resource abuse; use the pinned network-isolated CI container for an additional OS boundary.

Passing an adapted policy fixture establishes only its behavior on this table, these roles, claims and operations. It does not validate unchanged application migrations, other tables, views, functions, grants, anonymous access, concurrency, deployments or production security. A full application-schema adapter remains future work. The HTTP checks remain the separate bundled HTTP fixture, not your application's API.

## Lifecycle and failure evidence

TCP listening is disabled. The server uses a newly created private Unix-socket directory with no inherited database environment/configuration. New-cluster local socket authentication requires no password; this affects only the disposable cluster, never host services or existing databases. Files and SQL error bodies are not copied into receipts.

Commands have deadlines and bounded output. Every planned database assertion not reached is inconclusive. SIGINT/SIGTERM cancel active subprocesses and initiate cleanup. A forced server crash, SQL timeout, unavailable runtime, invalid fixture contract or unconfirmed cleanup remains visible. A kernel kill, machine crash or SIGKILL of the CLI itself cannot run JavaScript cleanup; do not claim cleanup from an absent receipt. The temporary process/directory may then require operator inspection. The runner never performs broad process kills or deletes unrelated paths.

Run `THREATRECEIPT_REQUIRE_POSTGRES=1 node --test test/postgres.test.js` to require actual PostgreSQL tests locally. Without that flag, the suite skips database tests if tooling is unavailable. CI additionally runs them against an immutable official PostgreSQL 16.13 image with networking disabled, a non-root user, read-only source and a temporary writable filesystem.
