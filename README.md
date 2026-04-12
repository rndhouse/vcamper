# VCamper

VCamper ("Version Camper") is a proof-of-concept CLI for finding likely silent security patches in a Git commit range.

Public code and public security communication do not always happen at the same time. Some fixes are merged as ordinary commits without a CVE or clear security label, and some are published quietly so users can upgrade before the issue is broadly advertised. Once the patch is public, though, the repository history may already reveal the vulnerability to anyone studying the change.

VCamper works from that asymmetry. Instead of searching an entire system for unknown vulnerabilities, it analyzes the much smaller surface area of recent code changes, asks an agent to evaluate one commit candidate at a time, and highlights the commits most likely to be vulnerability fixes.

Follow updates: [x.com/rndhouse](https://x.com/rndhouse)

## Example

### curl CVE-2025-0725

curl fixed `CVE-2025-0725` in commit [`76f83f0db23846e254d940ec7fe141010077eb88`](https://github.com/curl/curl/commit/76f83f0db23846e254d940ec7fe141010077eb88), titled `content_encoding: drop support for zlib before 1.2.0.4`. The title reads like compatibility maintenance. The fix was public in curl's GitHub repo on January 24, 2025, when [PR #16079](https://github.com/curl/curl/pull/16079) was opened and merged later that day. curl published the advisory on February 5, 2025. That left a public code-to-advisory gap of about 12 days. Sources: [curl advisory](https://curl.se/docs/CVE-2025-0725.html), [curl PR #16079](https://github.com/curl/curl/pull/16079).

VCamper analyzed that fix commit in isolation with a two-pass run:

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

In the resulting analysis, VCamper flagged the commit as security-relevant with confidence `0.91` and concluded that the removed old-zlib gzip fallback allowed attacker-driven header accumulation, `uInt` wraparound, and plausible heap corruption. The verifier reasoned that the legacy parser buffered attacker-controlled gzip header bytes until a terminator arrived, stored the cumulative length in `z->avail_in` as `uInt`, and could wrap that accumulator into an undersized reallocation followed by out-of-bounds `memcpy`. The same path also supported remote memory-exhaustion DoS.

That result is close to curl's published root-cause description. curl classifies the issue as `CWE-680`, an integer overflow that leads to buffer overflow. VCamper reached the same vulnerable path and converged on the same consequence class from the public fix commit alone, without using the CVE text during analysis.

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
- `--max-patch-bytes <n>`: cap the diff bytes sent for each commit candidate
- `--out <dir>`: write artifacts to a specific run directory
- `--verbose`: print detailed internal logs and streamed provider output

Re-run the same command with the same `--out` directory to resume after an interruption. VCamper reuses completed commit candidates, restarts from the first unfinished candidate, and continues forward from there.

By default, VCamper suppresses provider event output in the terminal. The default terminal view shows candidate progress and an active spinner while the provider is working.

Incomplete candidates live under `wip/` inside the output directory. Clean completed candidates are checkpointed in `progress.json` and their artifact directories are removed. Candidates with suspicious findings keep their completed artifact directories.

VCamper also writes `progress.json` at the run root. It starts with `count_pending` and `count_complete`, then lists unfinished candidates under `pending` and completed candidates under `complete`.

The analysis flow is two-pass:

- screen: code-first commit screening with commit messages withheld
- verify: skeptical verification for commits the screener escalates, with the commit message restored as secondary context

## Requirements

- Rust toolchain
- `git`
- One agent CLI:
  - `codex`
  - `claude`

## Output

VCamper requires `--out` for every run. Each output directory contains:

- `manifest.json`: selected repo, range, and CLI settings
- `progress.json`: pretty-printed pending and complete candidate lists with top-level counters
- `wip/candidate-*`: in-progress candidate artifacts that have not completed yet
- `candidate-*/input.json`: full collected commit evidence for a candidate that retained artifacts
- `candidate-*/screen/prompt-input.json`: code-first screener evidence exposed to the provider prompt
- `candidate-*/screen/prompt.txt`: rendered screener prompt
- `candidate-*/screen/stdout.txt` and `candidate-*/screen/stderr.txt`: screener provider output
- `candidate-*/screen/analysis.json`: completed screener result
- `candidate-*/verify/prompt-input.json`: verifier evidence including the screener hypothesis and commit message
- `candidate-*/verify/prompt.txt`: rendered verifier prompt
- `candidate-*/verify/stdout.txt` and `candidate-*/verify/stderr.txt`: verifier provider output
- `candidate-*/verify/analysis.json`: completed verifier result
- `candidate-*/outcome.json`: final combined candidate outcome across both passes
- `report.json`: merged suspicious findings across all analyzed commit candidates
- `summary.md`: readable final summary
