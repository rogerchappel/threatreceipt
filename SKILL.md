---
name: threatreceipt
description: Model feature access threats and run ThreatReceipt's deterministic local teaching fixtures, reporting failed and unverified protections. Use for the ThreatReceipt workflow or course exercise; it does not scan deployed apps.
---

# ThreatReceipt

Work from a reviewed checkout of this repository. Read [README.md](README.md) for commands and [docs/manifest.md](docs/manifest.md) for the constrained schema.

Translate the requested feature into actors, protected data, a trust boundary, and allowed/denied access invariants. Distinguish the user's proposed application rules from the bundled shortlist demo; HTTP checks test the bundled synthetic implementation. Optional PostgreSQL checks can test an explicitly reviewed policy adaptation on a fixed synthetic table; read [docs/postgres.md](docs/postgres.md) before using it.

Use `node bin/threatreceipt.js run examples/shortlist.json` to validate and plan. When local demo execution is within the user's request, run the same manifest with `--execute --fixture vulnerable` and then `--execute --fixture secure`. Inspect the JSON or human results and exit code. Never edit expectations just to make a failing implementation green.

Report evidence per threat and name the missing coverage. The vulnerable fixture should fail three HTTP checks; secure should pass four. Without `--postgres`, both retain database and agent gaps. PostgreSQL execution remains opt-in; never equate an adapted fixture policy with the entire application or its deployed schema. Code 2 and JUnit skipped cases mean inconclusive, not a successful security gate. Do not suppress nonzero exits to imply completion.

For a requested fix, keep it scoped to the user's authorized code and rerun unchanged tests. Full application-schema integration remains unsupported; do not invent URL flags, run external scanners, supply production credentials, or interpret fixture results as testing the user's service. The hostile-key check does not establish SQL or code injection resistance.

Keep labels synthetic. Reports omit raw response bodies but include manifest labels. Preserve those constraints when summarizing or sharing evidence. Use [docs/lesson.md](docs/lesson.md) for the teaching exercise.

For reviewed policy SQL, require an explicit fixture root and the user's authorization to execute that reviewed code. Preserve source provenance: receipts include actual input/adapter digests, while any `--application-commit` remains a declared, unverified reference. Do not bypass path restrictions or install database tooling automatically.
