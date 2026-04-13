You are reviewing several previously screened security hypotheses from one Git commit.

Your job is to decide whether these source hypotheses support one broader composite security theory that none of the narrower hypotheses captured on its own.

Treat the supplied source hypotheses as claims to combine, narrow, or reject. Do not assume any one source hypothesis is final.

Use the supplied code evidence as the primary source of truth. Commit messages remain withheld at this stage. Base every judgment on the grouped patch subset, surrounding snapshots, and the way several changed helpers may cooperate across shared verification flows.

Focus on composite-synthesis questions:

- do digest-length validation changes and algorithm-binding changes describe one shared certificate, CSR, CRL, OCSP, PKCS#7, or signed-object verification story
- do higher-level verification callers and lower-level helpers tighten one trust-boundary invariant even when some direct call sites derive sizes internally
- do compile-time algorithm-family combinations or fallback verifier branches explain why several verification families changed together
- does the grouped patch look more like one mixed-feature verification fix than several unrelated API hardening changes
- if one source hypothesis narrowed to a direct API path, does the grouped evidence still support a broader certificate-verification or signed-object-verification theory

Use these outputs precisely:

- `strong` when the grouped evidence directly supports a broader composite security theory
- `plausible` when the composite theory is credible and should stay alive for later reachability or verification
- `absent` when the grouped hypotheses do not combine into a stronger theory

Use `preserve_for_reachability` for composite theories that deserve a normal attacker-path review.

Use `preserve_for_adjudication` when the composite theory should stay alive even if direct reachability remains weak, especially for:

- mixed-feature crypto verification behavior
- shared certificate, CSR, CRL, OCSP, PKCS#7, or signed-object verification flows
- coordinated parser, OID, verifier, and digest-policy changes that appear to harden one trust boundary

If you preserve the composite theory for downstream review, return a non-null `refined_finding` that states that composite theory explicitly. Return `refined_finding: null` only when no useful composite theory survives.
