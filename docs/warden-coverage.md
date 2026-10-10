# Continuous WARDEN coverage

MOMUS tests a **local WARDEN build** with synthetic MCP definitions. Nothing starts
an MCP server, calls a generated tool, reads the named decoy file or contacts a
payload destination. The adapter invokes WARDEN's real static → threat → origin →
pinning chain with a fixed, neutral server identity, built-in threat feed and fresh
in-memory pins. `blockAtSeverity` is `high`; remote feeds and LLM classification are
not part of this measurement.

The original matrix has five intents, six languages (English, Russian, Spanish,
Chinese, German, Japanese), two native formulations, nine placements and eight
encodings. These are actual translated clauses, not prefixes on English text.
Placements include nested schemas and metadata; encodings include zero-width
characters inside words, homoglyphs, fullwidth, base64, HTML entities, literal
Unicode escapes, and fullwidth combined with zero-width characters.

There are 4,320 combinations, **4,194 distinct attack inputs** after content
deduplication, and **36 benign controls**. An encoding that changes no characters
adds no evidence. The offline generator is finite and does not pretend repeated
inputs are newly invented attacks. `--llm` adds bounded new proposals using the
existing `MOMUS_LLM_*` provider configuration.

## Run locally

From the monorepo root, with Python 3.11+ and Node 20+:

```sh
npm --prefix warden ci
python -m pip install -e './oracles/core[pqc]' -e './momus[dev]'
python -m momus.engine.coverage_campaign run \
  --warden ./warden --data-dir ./momus/data/warden-coverage --fresh 8000
```

`npm ci` runs WARDEN's build lifecycle. After changing its source, rebuild with
`npm --prefix warden run build`. `--warden` accepts either a package directory
(including an installed `@aimarket/warden`) or its `dist/index.js`. The `.mjs`
adapter ships inside the MOMUS wheel; no comparison scripts from the WARDEN source
tree are required. The installed `momus-coverage` command is equivalent to
`python -m momus.engine.coverage_campaign`.

For continuous operation:

```sh
momus-coverage run --warden ./warden \
  --data-dir ./momus/data/warden-coverage --rounds 0 --interval 3600 --llm
```

Without `--llm`, there are no model requests. With it, each round makes at most one
request (45-second deadline), requesting up to eight proposals by default
(`--llm-limit`, maximum 16). Each proposal yields a plain case and one mutation.
The prompt receives up to four previously allowed non-benign definitions as
untrusted examples. Accepted descriptions may use only synthetic destination and
credential placeholders; the model cannot change the scanner, policy or targets.
Provider errors and invalid JSON are recorded under `generation`; deterministic
coverage continues. The offline provider reports `offline`, never fabricated text.

Each round:

1. Runs the same 60 plain attack descriptions and 36 benign controls as a baseline.
2. Selects unseen, content-deduplicated inputs using the seed and durable round ID
   (256 template inputs by default, plus accepted model proposals).
3. Replays up to 128 older inputs, reserving capacity for both misses and other
   decisions, oldest-tested first. This catches improvements and regressions.
4. Records exact inputs, gate findings, ruleset digest, a digest of the build's JS
   files, policy, generation provenance and decisions in SQLite, then exports JSON.

`--max-cases` (default 20,000) limits the live corpus. Once full, new inputs stop
being admitted and the existing corpus continues to be replayed. The seed
reproduces deterministic selection given the same corpus and round ID; model output
is reproduced by replaying saved input bytes, not by calling the model again.
Round history and artifacts are retained, so provision/archive their storage for
long-running deployments. Keep SQLite, its WAL and exports on a persistent volume.
A process lock prevents overlapping rounds or reviews in the same directory.

## Reports and exact replay

`latest.json` contains the newest committed report. `rounds/000001/` contains:

| File | Meaning |
| --- | --- |
| `report.json` | Counts, per-dimension recall, baseline/fresh/replay cohorts, changes, build identity |
| `cases.json` | Exact definitions, labels, fingerprints, provenance, full gate findings and previous decisions |
| `misses/<fingerprint>.json` | Labelled attacks WARDEN allowed, in `{name, tools}` replay format |
| `false-positives/<fingerprint>.json` | Benign controls that WARDEN blocked |
| `candidates/<fingerprint>.json` | Allowed model proposals whose intent has not been independently reviewed |

```sh
# Run the exact saved inputs against the current build; append a new round.
momus-coverage replay --warden ./warden \
  --data-dir ./momus/data/warden-coverage --round 1

# Rebuild exports from SQLite after an interrupted write.
momus-coverage export --data-dir ./momus/data/warden-coverage --round 1
```

Historical rounds and their labels are immutable. Exporting an older round does
not replace `latest.json`. A later review changes future live-corpus measurements,
not the evidence recorded in a past round.

Recall is `blocked / evaluated` over **labelled attacks only**. Missing decisions,
malformed adapter results, timeouts, and `GATE_ERROR` are inconclusive, not misses
or successful blocks. The report exposes all error counts, and an entirely failed
measurement has `recall: null`. Benign false-positive rate and unreviewed candidate
counts are separate. A candidate allowed by WARDEN is not proof of a vulnerability.

The aggregate mixes fresh and previously selected inputs; compare the fixed
`cohorts.baseline` or replay an identical round for a fair build comparison.
`fixed` and `regressed` describe changed scanner decisions on matching content and
labels. They do not prove exploitability or remediation of a live service. Synthetic
encoding coverage is not an agent attack-success rate. The controls are a small
regression sample, not an estimate of false positives across the MCP ecosystem.

## Review model proposals

Inspect a proposal and its parent in `cases.json`, then record your assessment:

```sh
momus-coverage review --data-dir ./momus/data/warden-coverage \
  --fingerprint SHA256_FROM_CASES --label malicious \
  --note 'Reviewed the instruction and confirmed the claimed hostile intent.'
```

Use `--label benign` when the proposal is harmless. Only explicit human review
promotes a model proposal into a labelled denominator; the model never grades
itself. The review log persists in SQLite. A change of label clears the previous
comparison decision so relabelling cannot create a false regression.

## Service and CI

[`../deploy/warden-coverage.service`](../deploy/warden-coverage.service) is a Linux
systemd service template. Adjust its user and paths to an existing MOMUS installation,
provide a built WARDEN package and a persistent state directory. It runs offline by
default; add `--llm` to `ExecStart` in an override to enable your provider and put
`MOMUS_LLM_*` settings in `/etc/momus/coverage.env`. SIGINT/SIGTERM stop the worker;
committed SQLite evidence survives restarts. This file does not install or activate
itself.

The monorepo workflow `.github/workflows/momus-coverage.yml` runs on affected changes,
manually, and daily. It builds WARDEN, tests the integration, checks wheel contents,
runs the complete matrix, verifies exact replay and retains reports for 14 days.
Each CI job starts a fresh corpus; the service's persistent corpus is what tracks
history between deployments. Neither path publishes a threat-feed record, pays a
bounty, or changes WARDEN rules automatically.

Exit codes: `0` complete measurement; `1` a regression or new false positive with
`run --fail-on-regression`; `2` invalid configuration or an incomplete evaluation;
`130` interrupted. Existing known misses are reported without making every run fail.
LLM generation failure is shown independently from gate evaluation status.

## Expanded corpus and WARDEN 0.11.0

Campaigns default to `--suite expanded`; `--suite baseline` preserves the v2
pool. The extended suite contains 8,244 distinct attacks in 11 languages and
362 benign controls. Every original input is retained. Added languages: Arabic,
Hindi, Korean, Swahili and Turkish. Added encodings: percent, hexadecimal HTML
entities and nested base64/percent. These are author-labelled synthetic probes,
not independent human-reviewed examples or measured successful exploits.

```sh
python -m momus.engine.coverage_compare --before /path/to/warden-v10 \
  --after ../warden --out data/warden-v11-comparison \
  --public-corpus ../warden/docs/data/mcp-corpus-2026-10-01.jsonl.gz
```

This freezes `cases.jsonl.gz`, saves per-case `decisions.jsonl.gz`, `report.json`
and optional `public-corpus.json`. Recognition, strict admission, drift after
approval and approved benign controls are measured separately. An admission
refusal is not a detected attack.

The live evaluator uses WARDEN's compiled classifier and the exact frozen tool
contents. It sends no fixture labels, never executes tools, and records incomplete
inspections separately. Configure `WARDEN_CLASSIFIER_URL`,
`WARDEN_CLASSIFIER_MODEL` and the secret `WARDEN_CLASSIFIER_API_KEY`.
Optionally set `WARDEN_CLASSIFIER_REASONING_EFFORT` to a provider-supported
`none`, `low`, `medium` or `high`; it is part of the saved run identity.
The DeepSeek run uses `none` so hidden reasoning does not consume the final JSON
output budget. Then run:

```sh
node momus/engine/coverage_semantic.mjs ../warden \
  data/warden-v11-comparison/cases.jsonl.gz data/semantic-pilot 80
# Omit 80 and use a new output directory for the full corpus.
```

A numbered pilot balances attacks and benign controls where controls are
available. Full runs use eight fixtures per request and four workers. Resume
requires identical corpus/model/prompt/build identity; failed inspections remain
explicit failures. Model nondeterminism means semantic replay need not be
byte-identical to the static replay.

The classifier returns one decision per tool and references numbered source
fields. WARDEN validates IDs and builds evidence previews from the actual input.
Each malformed/incomplete decision is retried once on that tool alone; provider
outages do not trigger a batch of retries. Long inputs exceeding the complete
inspection budget and remaining uncertainty are still refused, not called attacks.

After both full runs, join recognition outcomes without mixing in approval refusals:

```sh
python -m momus.engine.coverage_summary --static data/warden-v11-comparison \
  --semantic data/warden-semantic-full-deepseek-v11 --out docs/coverage-v11.json
```

This checks matching corpus/build hashes and complete unique case IDs. In v12,
the live runner also invokes the real WARDEN gate chain with its byte-bound
semantic review and records `reviewedStatic`. This permits only the production
exceptions for readable encoded text and structured quotation ambiguity. The
summary uses that gate verdict, rather than OR-ing an obsolete offline verdict
back in. A gate block or a completed semantic high finding counts as detection.
Historical v11 rows without `reviewedStatic` retain their original static-OR semantics. If neither detects
an attack and an inspection failed, the result is incomplete, never allowed.
The report retains false-block and missed-attack IDs for exact replay. `responses.jsonl`
contains synthetic tool text and model output with token counts and finish reasons;
it never contains credential headers or model reasoning traces. Reports record no
key, and reruns never silently replace a result from a different build or prompt.

The recorded WARDEN 0.11.0 result is in [coverage-v11.json](coverage-v11.json):
8,228/8,244 attacks blocked with static rules plus DeepSeek at `high`, 32/362
benign controls blocked, zero incomplete inspections. On the original 4,194
attack inputs, the combined result is 4,184 versus the old static-only 1,620.
Without the optional classifier, new static rules block 2,808/8,244 and 1,692/4,194.
These synthetic, related inputs are not a held-out evaluation of all languages.


The recorded **WARDEN 0.12.0** result is in [coverage-v12.json](coverage-v12.json):
8,244/8,244 attacks blocked at `high`, 1/362 benign controls falsely blocked
(0.28%, previously 8.84%), zero incomplete inspections. All 16 old misses and
32 old false blocks are corrected; one new Spanish encoded task-description
false block remains. Offline results remain 2,808/8,244 and 31/362, with no
attack regressions. This is the same synthetic stress corpus used during
engineering, not a new held-out benchmark. The [nine-part implementation audit](mcp-quality-review.md)
separately records gaps in HISTOR sandbox behavior, THEMIS and wrap results.

```sh
python -m momus.engine.coverage_summary --static data/warden-v12-comparison \
  --semantic data/warden-semantic-full-v12-bound --out docs/coverage-v12.json
```
