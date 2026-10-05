# Manifest version 1

See [the runnable manifest](../examples/shortlist.json).

The root has exactly `version`, `feature`, and `threats`. Version must be integer 1. `feature` and threat `id` are lowercase ASCII labels matching `[a-z][a-z0-9-]{0,63}`. Use synthetic, non-sensitive labels. Threat IDs must be unique; the `coverage-` prefix is reserved for generated coverage entries. Database subcase IDs append a colon and internal case name, which cannot collide with manifest IDs. `threats` contains 1–32 objects, each with exactly `id` and `check`. The file must be a regular UTF-8 JSON file of at most 16 KiB. Comments and executable configuration are unsupported.

| Check | Fixed invariant |
| --- | --- |
| `owner-read` | Owner receives exactly the intended synthetic record |
| `cross-tenant-read` | Other tenant receives 403 without record data |
| `anonymous-read` | Missing demo identity receives 401 without record data |
| `literal-input` | Hostile key receives 404 without record data |
| `postgres-rls` | Actual two-tenant CRUD when `--postgres` is selected; otherwise inconclusive |
| `agent-injection` | Unavailable: model/tool behavior not verified |

The four HTTP checks are required together; removing the positive case cannot make a deny-all implementation pass. Unsupported coverage is added to reports even when omitted from the manifest. Unknown runners, keys, URLs, headers, secrets, commands and expected-status overrides are rejected. Expectations come from reviewed code, not an agent-supplied expected answer.

`--execute` starts one fixture at a dynamically assigned port on numeric IPv4 loopback. The CLI constructs all GET paths internally, sends no supplied credentials, refuses redirects, caps responses at 8 KiB, and applies a two-second request deadline. No `--target` or existing service connection is supported. The optional [PostgreSQL adapter](postgres.md) owns its private local cluster; it does not accept database targets. Unknown checks still fail manifest validation. Declared but unsupported checks, such as `agent-injection`, remain inconclusive. The HTTP helper is internal and not a public arbitrary-target API.

Exit codes: 0 complete pass (reserved), 1 any failed invariant, 2 missing/unexecuted coverage or transport failure, 64 invalid input or inability to start the local fixture. A failure takes precedence over inconclusive coverage.

Receipt schema version 2 hashes the canonical manifest (object keys sorted recursively, array order preserved, compact JSON encoded as UTF-8). SQL hashes cover loaded UTF-8 source. Provenance appears in JSON, human output and JUnit properties. `--application-commit` accepts a full lowercase hex Git revision and marks it `independentlyVerified: false`. It does not read that repository or verify its migrations.
