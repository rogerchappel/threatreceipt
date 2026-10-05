# Existing tools and future adapters

Research checked 2026-10-05. No tools below are installed, invoked or bundled by ThreatReceipt. The optional PostgreSQL adapter uses installed PostgreSQL binaries and original SQL assertions, not pgTAP. This file is an integration plan, not a claim of implemented coverage.

| Tool | Useful capability | License / integration boundary |
| --- | --- | --- |
| [pgTAP](https://github.com/theory/pgtap) with [Supabase database testing guidance](https://supabase.com/docs/guides/local-development/testing/pgtap-extended) | Actual role/JWT-context allowed and denied database operations with transactional fixtures and TAP results | Verify the selected pgTAP version's PostgreSQL license and extension distribution before integration; docs are references, not copied tests |
| [Schemathesis](https://github.com/schemathesis/schemathesis) | OpenAPI/GraphQL generated edge cases and custom business invariants | MIT; future separately installed, pinned adapter; ownership rules still need explicit assertions |
| [Promptfoo](https://github.com/promptfoo/promptfoo) | Fixed trusted prompt fixtures with deterministic assertions and JSON/JUnit output | MIT core; future offline mocked-tools evaluation only, no cloud graders or remote-only red-team generators |
| [Semgrep](https://docs.semgrep.dev/licensing) | Static code checks | CE engine and registry rule licenses differ; no registry rules bundled. Review individual rules before any later adapter |

ThreatReceipt's added value is traceability: a feature's threat is tied to a reviewed invariant, runner outcome, fix and reproducible evidence. It does not replace these tools or reimplement their scanners.

## PostgreSQL acceptance criteria before claiming coverage

Use a disposable local database with known synthetic rows and separate owner/other-tenant/anonymous roles. Check allowed and denied SELECT, INSERT, UPDATE and DELETE, including grants, non-owner execution context, JWT claims where applicable, RLS bypass/superuser hazards, and cross-tenant side effects. Roll back transactions and verify cleanup. Do not infer RLS protection from HTTP 403s or merely finding RLS enabled. The current [PostgreSQL adapter](postgres.md) implements two-tenant CRUD and transactional evidence on bundled synthetic policies only. External/reviewed SQL is disabled pending independent security validation. Anonymous-role behavior and full application-schema integration remain unverified. Without executing this adapter, database coverage remains inconclusive.

## Adapter execution boundary

Review and pin each adapter, engine and config. A scanner configuration can execute code or transmit data; an offline option is not an egress firewall. Do not automatically download or execute arbitrary manifests/configs. Future runners need explicit synthetic target allowlists, bounded time/output, rollback ownership and evidence normalization that excludes raw secrets.

See [Schemathesis migration guidance](https://github.com/schemathesis/schemathesis/blob/master/MIGRATION.md), [Promptfoo output formats](https://www.promptfoo.dev/docs/configuration/outputs/) and [Promptfoo data handling](https://www.promptfoo.dev/docs/red-team/troubleshooting/data-handling/). Raw evaluator reports may include prompts/configuration/outputs; JUnit is not a guarantee of redaction.
