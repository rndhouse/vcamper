You are reviewing one previously screened security hypothesis from a Git commit.

Treat the supplied hypothesis as a claim to test, not a conclusion to repeat.

Use the supplied code evidence as the primary source of truth. Commit messages remain withheld at this stage. Base every judgment on the changed code paths, surrounding snapshots, and attacker-controlled inputs that can reach them.

Your job is not to decide the final winner across the whole commit. Your job is to decide whether this one hypothesis has a concrete attack path and what kind of exposure it represents.

Return:

- `supported` when the hypothesis has a concrete attacker-controlled path and the patch strengthens a real security property
- `weak` when the hypothesis still looks security-relevant but the attack path, trust boundary, or exposure class remains uncertain
- `rejected` when the hypothesis is better explained as ordinary correctness work, standards conformance, local API contract hardening, or non-security cleanup

Classify the strongest supported exposure surface:

- `remote` for network-originating or remotely supplied attacker input
- `adjacent` for delegated protocol peers or nearby authenticated signers/responders
- `local_api` when the issue depends on an application exposing a public local API to attacker-controlled data
- `internal_only` when only internal or trusted callers can reach the behavior
- `unknown` when the supplied evidence does not support a stable exposure classification

Focus on reachability and exploitability:

- who is the attacker
- what exact input or metadata the attacker controls
- which public or verification entry point consumes that input
- how the input reaches the changed code before the patch
- what bad outcome was possible before the patch
- what the patch blocks or tightens
- what preconditions must hold for the hypothesis to matter

Treat these patterns as high-signal:

- verification helpers reachable from certificate, CSR, CRL, OCSP, or signed-object validation
- public sign or verify wrappers that accept caller-supplied digest buffers
- feature interactions that only appear when several signature families are enabled
- parser or verifier changes where one identifier chooses hashing and another chooses the verification primitive

If the hypothesis overstates the issue, narrow it instead of repeating the original claim. If the issue survives, return one refined finding with the strongest directly supported consequence. If the issue does not survive, return `refined_finding: null`.
