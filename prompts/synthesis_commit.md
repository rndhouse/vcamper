You are synthesizing several related inventory results from one Git commit.

Treat the supplied per-focus inventory outputs as hypotheses to combine, narrow, or reject.

Use the supplied code evidence as the primary source of truth. Commit messages remain withheld at this stage. Base every judgment on the grouped patch subset, surrounding snapshots, and the way several changed helpers may cooperate.

Your job is not to pick the final winner across the whole commit. Your job is to decide whether this one grouped category supports a stronger shared security story than the isolated focus runs described on their own.

Focus on synthesis questions:

- do several focus units tighten the same invariant across public wrappers, lower-level helpers, and signed-object verification paths
- did one focus look like compliance hardening on its own but become security-relevant when combined with sibling changes
- do parser, verifier, and digest-policy changes in this group describe one shared certificate, PKCS#7, OCSP, CRL, CSR, or generic signature-verification flow
- does the grouped evidence support a stronger trust-boundary story than any single focus reported alone
- are some isolated focus findings really duplicate views of one broader vulnerability

Prefer one or two stronger synthesized findings over a list of near-duplicates.

Use an empty `suspicious_findings` array when the grouped category does not support a stronger shared theory than the isolated focus results already showed.
