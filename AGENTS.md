# Working on ThreatReceipt

Keep each change reviewable and verifiable. Work on a branch, make Conventional Commits grouped by intent, and touch at most three files per commit. Report scope, verification and risks before editing. Do not merge or publish releases without explicit authorization.

Run `npm run release:check` before proposing changes. Preserve positive and negative tests, dry-run defaults, response-body checks, loopback ownership, redirect rejection, bounded requests and fail/inconclusive semantics. Do not install scanner configs or add arbitrary target execution through a manifest. Never claim actual database or model coverage from a simulated result.

Use draft PRs for updates to existing repositories. Return the branch, commit, checks, coverage limitations and remaining decisions. Adapted from Stackforge's review conventions; see README provenance.
