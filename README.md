# VCamper

VCamper ("Version Camper") is a proof-of-concept CLI for finding likely silent security patches in a Git commit range.

Public code and public security communication do not always happen at the same time. Some fixes are merged as ordinary commits without a CVE or clear security label, and some are published quietly so users can upgrade before the issue is broadly advertised. Once the patch is public, though, the repository history may already reveal the vulnerability to anyone studying the change.

VCamper works from that asymmetry. Instead of searching an entire system for unknown vulnerabilities, it analyzes the much smaller surface area of recent code changes, asks an agent to evaluate one commit candidate at a time, and highlights the commits most likely to be vulnerability fixes.

Follow updates: [x.com/rndhouse](https://x.com/rndhouse)

## Example

### curl CVE-2025-0725

curl fixed `CVE-2025-0725` in commit [`76f83f0db23846e254d940ec7fe141010077eb88`](https://github.com/curl/curl/commit/76f83f0db23846e254d940ec7fe141010077eb88), titled `content_encoding: drop support for zlib before 1.2.0.4`. The title reads like compatibility maintenance. The fix was public in curl's GitHub repo on January 24, 2025, when [PR #16079](https://github.com/curl/curl/pull/16079) was opened and merged later that day. curl published the advisory on February 5, 2025. That left a public code-to-advisory gap of about 12 days. Sources: [curl advisory](https://curl.se/docs/CVE-2025-0725.html), [curl PR #16079](https://github.com/curl/curl/pull/16079).

VCamper analyzed that fix commit in isolation with a single end-to-end run:

```bash
cargo run -- analyze \
  --repo /path/to/curl \
  --from 76f83f0db23846e254d940ec7fe141010077eb88 \
  --to 76f83f0db23846e254d940ec7fe141010077eb88 \
  --provider codex \
  --model gpt-5.4 \
  --screen-effort medium \
  --verify-effort high \
  --out /tmp/vcamper-curl-cve-2025-0725
```

In the resulting analysis, VCamper flagged the commit as security-relevant with confidence `0.95` and concluded that the removed old-zlib gzip fallback allowed a remote server to keep curl clients buffering attacker-controlled gzip header bytes without a bound until memory was exhausted. The verifier reasoned that the legacy parser stayed in `GZIP_UNDERFLOW` while optional gzip header fields lacked their terminating NUL, and curl kept reallocating and appending attacker-supplied bytes to `z->next_in` without decompression progress. The strongest supported consequence in the current pipeline is remote client-side memory-exhaustion DoS.

That result still lands on the right vulnerable path from the public fix commit alone, without using the CVE text during analysis. The current pipeline is more conservative about consequence class than curl's published advisory: curl classifies the issue as `CWE-680`, while VCamper now stops at a well-supported remote resource-consumption bug in the same old-zlib fallback parser.

### wolfSSL CVE-2026-5194

wolfSSL fixed [`CVE-2026-5194`](https://app.opencve.io/cve/CVE-2026-5194) in commit [`abce5be989ccd0665e2b9445abb856886975dfd1`](https://github.com/wolfSSL/wolfssl/commit/abce5be989ccd0665e2b9445abb856886975dfd1) from [PR #10131](https://github.com/wolfSSL/wolfssl/pull/10131), titled `20260403-WC_FIPS_186`. This is a harder case than curl. The patch mixes FIPS 186 compliance work, test updates, signature-OID checks, and digest-length checks across `wolfcrypt/src/asn.c`, `wolfcrypt/src/ecc.c`, `src/pk_ec.c`, `src/internal.c`, and `wolfcrypt/src/pkcs7.c`.

That commit is a good example of why VCamper has staged Codex passes. A single broad prompt drifted toward the wrong local bug story. The staged pipeline surfaced three distinct verified findings from the same commit instead:

- a shared ASN.1 `signatureAlgorithm` / key-family binding flaw in `ConfirmSignature`
- a direct pre-hash ECDSA verification bug on the public wrapper path
- a broader composite signed-object verification theory that ties algorithm binding to shared ECDSA digest-policy enforcement

The composite finalist is the interesting one. In the final staged run, VCamper confirmed a `0.90` finding that signed-object verification let attacker-controlled signature OIDs steer ECDSA verification to mismatched or below-policy digests. That is not an exact restatement of the published CVE, which also emphasizes mixed EdDSA / ML-DSA enablement, but it lands in the same patch family and shows useful behavior on a noisy crypto commit: VCamper preserved multiple theories, verified them independently, and recovered the shared verification boundary instead of forcing one winner too early.

One end-to-end command is enough to show the current prototype behavior on this commit:

```bash
cargo run -- analyze \
  --repo /path/to/wolfssl \
  --from abce5be989ccd0665e2b9445abb856886975dfd1 \
  --to abce5be989ccd0665e2b9445abb856886975dfd1 \
  --provider codex \
  --model gpt-5.4 \
  --screen-effort xhigh \
  --verify-effort xhigh \
  --inventory-focuses 0,1,3,4,9 \
  --out /tmp/vcamper-wolfssl-cve-2026-5194
```

That command still uses a curated hotspot shortlist because this commit is unusually noisy. The point of the example is not that VCamper reproduces the CNA text exactly. The point is that it still recovers the right patch family and a useful composite signed-object verification theory from a commit that looks like compliance churn on first read. This is the current ceiling of the prototype on hard crypto commits: it can recover the shared trust boundary and multiple verified security stories, but exact CVE narrative matching still depends on stronger mixed-feature reasoning in later stages.

## Usage

```bash
cargo run -- analyze \
  --repo /path/to/repo \
  --from <older-release-commit> \
  --to <newer-release-commit> \
  --provider codex \
  --model gpt-5.4 \
  --screen-effort medium \
  --verify-effort high \
  --out /tmp/vcamper-run
```

Useful flags:

- `--dry-run`: collect Git evidence and render prompts without invoking an agent CLI
- `--model <name>`: pass an explicit model name to the selected provider
- `--effort <low|medium|high|xhigh>`: set both screening and verification effort in one flag
- `--screen-effort <low|medium|high|xhigh>`: set the first-pass screener effort
- `--verify-effort <low|medium|high|xhigh>`: set the second-pass verifier effort
- `--max-commits <n>`: fail fast when the range is larger than expected
- `--max-patch-bytes <n>`: cap the diff bytes stored in truncated commit artifacts and inline fallback prompts
- `--out <dir>`: write artifacts to a specific run directory
- `--start-at-stage <inventory|synthesis|interaction|composite_synthesis|reachability|verify>`: start from a specific staged Codex boundary and reuse earlier stage artifacts from the same `--out` directory
- `--stop-after-stage <inventory|synthesis|interaction|composite_synthesis|reachability|verify>`: stop after a staged Codex boundary so you can inspect one stage in isolation
- `--inventory-focuses <i,j,...>`: restrict Codex inventory to a specific hotspot-focus shortlist while preserving the original focus indexes in artifacts
- `--rerun-stages <inventory,synthesis,interaction,composite_synthesis,reachability,verify>`: clear the named stage and every downstream stage before continuing from the same `--out` directory
- `--verbose`: print detailed internal logs and streamed provider output

Re-run the same command with the same `--out` directory to resume after an interruption. VCamper reuses completed commit candidates, restarts from the first unfinished candidate, and continues forward from there. Stage-scoped Codex runs also reuse earlier stage artifacts from the same `--out` directory, so you can execute inventory, synthesis, interaction, composite synthesis, reachability, and final verification in separate invocations without repeating completed work unless you pass `--rerun-stages`.

By default, VCamper suppresses provider event output in the terminal. The default terminal view shows candidate progress and an active spinner while the provider is working.

Incomplete candidates live under `wip/` inside the output directory. Completed candidates are checkpointed in `progress.json` and promoted out of `wip/` so prompt, provider, and analysis artifacts remain available for inspection after the run.

For Codex runs, VCamper persists a pass-local evidence bundle and points the model at files instead of embedding the full patch directly in the initial prompt. Each pass gets an untruncated `evidence/patch.diff`, `evidence/changed-files.txt`, `evidence/hotspots.json`, and before/after snapshots for changed files. Codex screening now runs as five staged invocations plus independent finalist verification inside each candidate:

- inventory: derive a ranked hotspot plan from the full patch and run one narrow focus prompt per hotspot file so the first-stage theories do not compete inside one broad prompt
- synthesis: merge related inventory results into stronger shared theories before later stages prune or rank them
- interaction review: inspect each hypothesis for mixed-feature, shared-flow, or compile-time interaction signals that ordinary reachability review could miss
- composite synthesis: combine surviving interaction theories into broader mixed-feature or shared-verification finalists without deleting the narrower source theories
- reachability: review each inventoried hypothesis in isolation with a smaller bundle and classify its exposure surface without prematurely discarding interaction-dependent theories
- verify: review each reachability survivor independently and keep every finalist that still verifies as a plausible security fix

That keeps each prompt narrower, makes stage progress inspectable, avoids losing diff context to prompt-size truncation, preserves interaction-heavy crypto theories when direct call paths stay incomplete, and lets final verification confirm multiple distinct theories from one noisy commit instead of forcing them to compete inside one prompt. Use `--stop-after-stage` to execute only one staged boundary when you want to inspect inventory, synthesis, interaction review, composite synthesis, or reachability before continuing. Use `--start-at-stage` to continue from a later boundary with the same `--out` directory. Use `--inventory-focuses` when you want to rerun only a shortlist of hotspot focus units through later stages.

VCamper also writes `progress.json` at the run root. It starts with `count_pending` and `count_complete`, then lists unfinished candidates under `pending` and completed candidates under `complete`. Pending candidates now include `active_stage`, so long Codex runs show whether a candidate is in inventory, synthesis, interaction, composite synthesis, reachability, or finalist verification.

The analysis flow is still reported as `screen` then `verify`, but Codex internally expands that into:

- `screen/inventory`: code-first focused hypothesis inventory with commit messages withheld
- `screen/synthesis`: category-level synthesis that combines related inventory results into stronger shared theories
- `screen/interaction`: one-hypothesis interaction review for shared verification flows, feature combinations, and compile-time branches
- `screen/composite_synthesis`: cross-category synthesis that adds broader composite theories on top of the surviving interaction hypotheses
- `screen/reachability`: one-hypothesis exploit-path review with compact bundles
- `verify`: one-finalist-at-a-time verification over reachability survivors, with the commit message restored as secondary context

## Requirements

- Rust toolchain
- `git`
- One agent CLI:
  - `codex`
  - `claude`

## Output

VCamper requires `--out` for every run. Each output directory contains:

- `manifest.json`: selected repo, range, CLI settings, and any inventory-focus shortlist used for the run
- `progress.json`: pretty-printed pending and complete candidate lists with top-level counters and per-candidate `active_stage`
- `wip/candidate-*`: in-progress candidate artifacts that have not completed yet
- `candidate-*/input.json`: collected commit evidence artifact for a completed candidate
- `candidate-*/screen/prompt-input.json`: code-first screener evidence exposed to the provider prompt
- `candidate-*/screen/prompt.txt`: rendered screener prompt
- `candidate-*/screen/evidence/patch.diff`: full untruncated patch for the screening pass
- `candidate-*/screen/evidence/changed-files.txt`: changed file list for the screening pass
- `candidate-*/screen/evidence/hotspots.json`: ranked hotspot files and screening focus units derived from the full patch
- `candidate-*/screen/evidence/file-snapshots.json`: manifest of before/after snapshots for changed files
- `candidate-*/screen/evidence/before/*` and `candidate-*/screen/evidence/after/*`: file snapshots available to Codex during screening
- `candidate-*/screen/inventory/cluster-*/prompt-input.json` and `prompt.txt`: focus-specific inventory evidence and prompt
- `candidate-*/screen/inventory/cluster-*/evidence/*`: filtered patch, hotspot plan, and snapshots for one inventory focus unit
- `candidate-*/screen/inventory/cluster-*/analysis.json`: one primary inventory result for that focus unit
- `candidate-*/screen/inventory/analysis.json`: merged inventory result before synthesis
- `candidate-*/screen/synthesis/category-*/prompt-input.json` and `prompt.txt`: category-level synthesis evidence and prompt
- `candidate-*/screen/synthesis/category-*/evidence/*`: grouped patch subset, hotspot plan, and snapshots for one synthesized category
- `candidate-*/screen/synthesis/category-*/analysis.json`: one synthesis verdict and any shared replacement theories for that category
- `candidate-*/screen/synthesis/analysis.json`: merged synthesis result before interaction review
- `candidate-*/screen/interaction/hypothesis-*/prompt-input.json` and `prompt.txt`: one-hypothesis interaction-review evidence and prompt
- `candidate-*/screen/interaction/hypothesis-*/evidence/*`: hypothesis-local patch subset, hotspot plan, and snapshots for interaction review
- `candidate-*/screen/interaction/hypothesis-*/analysis.json`: one interaction-review verdict, preservation decision, and refined finding
- `candidate-*/screen/interaction/analysis.json`: merged interaction-review summary before composite synthesis
- `candidate-*/screen/composite_synthesis/group-*/prompt-input.json` and `prompt.txt`: grouped composite-synthesis evidence and prompt
- `candidate-*/screen/composite_synthesis/group-*/evidence/*`: grouped patch subset, hotspot plan, source-hypothesis context, and snapshots for one composite theory review
- `candidate-*/screen/composite_synthesis/group-*/analysis.json`: one composite-synthesis verdict and any additive composite finding
- `candidate-*/screen/composite_synthesis/analysis.json`: merged screening result after additive composite synthesis
- `candidate-*/screen/reachability/hypothesis-*/prompt-input.json` and `prompt.txt`: one-hypothesis reachability evidence and prompt
- `candidate-*/screen/reachability/hypothesis-*/evidence/*`: hypothesis-local patch subset, hotspot plan, and snapshots
- `candidate-*/screen/reachability/hypothesis-*/analysis.json`: one reachability verdict and refined finding
- `candidate-*/screen/reachability/analysis.json`: merged screening result after reachability filtering
- `candidate-*/screen/stdout.txt` and `candidate-*/screen/stderr.txt`: screener provider output
- `candidate-*/screen/analysis.json`: completed screening result after staged inventory, composite synthesis, and reachability
- `candidate-*/verify/hypothesis-*/prompt-input.json` and `prompt.txt`: one-finalist verification evidence and prompt
- `candidate-*/verify/hypothesis-*/evidence/*`: finalist-local patch subset, hotspot plan, and snapshots for one verification pass
- `candidate-*/verify/hypothesis-*/analysis.json`: one finalist verification verdict and any confirmed findings
- `candidate-*/verify/hypothesis-*/stdout.txt` and `stderr.txt`: verifier provider output for one finalist
- `candidate-*/verify/results.json`: merged per-finalist verification records
- `candidate-*/verify/analysis.json`: completed verifier result
- `candidate-*/stage-state.json`: highest completed internal stage for the candidate and whether the full pipeline finished
- `candidate-*/outcome.json`: final combined candidate outcome across both passes
- `report.json`: merged suspicious findings across all analyzed commit candidates
- `summary.md`: readable final summary
