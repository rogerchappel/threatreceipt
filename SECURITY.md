# Security scope

ThreatReceipt 0.1 is a teaching fixture runner. It intentionally includes vulnerable behavior activated only through `--fixture vulnerable --execute`. The server binds to 127.0.0.1 on an ephemeral port, exists only for the command lifetime, uses synthetic data and supports only GET requests. Other processes on the same host can reach loopback; use an isolated development environment if that matters to your use.

There is no application target flag, shell execution, dynamic plugin loader, production probing, telemetry or credential handling. Development tooling uses pinned versions and a lockfile. Do not put secrets in manifest labels, which appear in reports.

If reporting a problem, provide only a minimal synthetic reproduction. Do not publish credentials, customer information, real exploit targets or sensitive response bodies in a public issue. Contact the repository owner to arrange a private disclosure channel before sending sensitive details. No private-reporting setting is assumed or changed by this project.
