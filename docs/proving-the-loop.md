# Proving the loop — the practice target, and why fixes reach production before `main`

> 🌐 **English** · [Русский](proving-the-loop.ru.md) · [Español](proving-the-loop.es.md) · [Français](proving-the-loop.fr.md) · [中文](proving-the-loop.zh.md)

> **Switch it to merge by itself** — one checkbox, with diagrams: [switch-to-auto-merge.md](switch-to-auto-merge.md).

> **The guards a patch passes** — [autonomous-repair-guards.md](autonomous-repair-guards.md) ·
> **Operator settings** — [self-healing-operations.md](self-healing-operations.md)

On 2026-08-30 the self-healing loop repaired a real defect three times, unattended, and was
verified from outside itself each time. This page is what that took, what it proved, and the
two things about it an operator has to know: **a fix reaches production before it reaches
`main`**, and **the canary can never be the thing the loop is proven on**.

## The loop was never actually tested, and nobody had noticed

Every real component passes its own contract checks — `gaia`, `oracles` and the hub all scan
clean, which is the point of building them carefully. So the only findings in the corpus were
the canary's, and the canary is a fixture that advertises a contract and knowingly breaks it.

Five autonomous repair attempts had been read as model failure. They were not. The file they
were asked to patch, `momus/canary/canary.py`, opens with:

> a deliberately non-conforming service … a service that advertises a contract and then
> knowingly breaks it … **Two things must stay true, and both are load-bearing for honesty.**

A careful model reads that and declines — and says so. Every one of those refusals was correct.
The attempts that *did* produce code were the worse answers: they were stepping over a
documented invariant.

**The canary structurally cannot be a source-repair target.** Its repair is a runtime toggle
(`POST /canary/fix` flips `STATE["fixed"]`) precisely because a source-level fix would make it
conforming for ever and it would never demonstrate a finding again. Repairing the canary
destroys the canary.

## PRAXIS — the missing target

`praxis/praxis.py`, port 9460, loopback only, no consumers, not federated. One file with a
genuine source-level defect, and a docstring that tells its main reader — a model — that
repairing it is the intended outcome.

The defect is not invented: it signs its manifest over `json.dumps` instead of the interop
canonical form. That is the exact mistake every autonomous attempt reached for when it could not
see the contract, and the one the ecosystem actually suffered when the oracle copy of
`manifest_canonical` fell behind the hub's fifth field and every oracle manifest failed
verification.

Its tests are designed to **fail while a drill is running** — three of four on the defect, four
of four on the repair — and the deploy hand runs them with `SKOPOS_AGENT_REQUIRE_TESTS=1`, so
the gate is what decides whether a repair was real. A patch that satisfies the probe by
reinventing the canonical form does not pass.

### Running a drill

```bash
# 1. break it, deliberately — a commit, not a toggle
#    (edit praxis/_signature_payload back to json.dumps, push to Gitea)

# 2. let MOMUS see it twice; the autopilot's rota does this on its own every 900s
curl -X POST http://127.0.0.1:9410/scan -H "x-momus-operator: $TOK" \
     -H 'content-type: application/json' -d '{"target":"praxis"}'

# 3. either wait for the autopilot, or dispatch by hand
curl -X POST http://127.0.0.1:9410/remediate -H "x-momus-operator: $TOK" \
     -H 'content-type: application/json' -d '{"finding_id":"<id>"}'
```

Wiring lives in four places and all four are required — a target added to only three of them
is scanned by nobody or repaired by nobody:

| Where | What |
|---|---|
| `web/backend/services/remediation_fix.py` | `DEFAULT_SCOPE["praxis"]` — which file may be patched |
| `skopos/skopos/remediation/recipes.py` | `_PRAXIS` — how to build it, and its test stage |
| `skopos/skopos/remediation/autopilot.py` | `DEFAULT_POLICY` and `DEFAULT_SCAN_ROTA` |
| the host | `/etc/skopos-deploy-hand/praxis.env`, and `MOMUS_EXTRA_TARGETS` on momus-backend |

The host wins over the code. `AUTOPILOT_SCAN_ROTA` in the env file overrides
`DEFAULT_SCAN_ROTA`, and a target added only to the source is never scanned — the autopilot
prints its rota at startup, which is the only reason this was caught.

## What was proven

Three drills, each verified from outside the loop: the manifest signature re-checked from the
verifier container, with a different key, against `oracle_core`'s canonical form.

| Dispatched | Patch author | Time | Result |
|---|---|---|---|
| 10:06 by hand | the plain fixer | 3 m 29 s | deployed, verified in place |
| 10:17 by hand | **the METIS council** | 10 m 11 s | deployed, verified in place |
| 10:51 **by the autopilot** | the plain fixer | 3 m 26 s | deployed, verified in place |

The third is the one that answers "does it repair defects automatically". The service was broken
at 10:32 and nobody touched anything after that: MOMUS saw the regression on its own rota, the
autopilot dispatched on its own schedule, and the chain ran to a verified deploy.

The patch, all three times, was the right one — it **imported** the canonical form rather than
rewriting it:

```diff
-    return json.dumps(manifest, sort_keys=True)
+    return _signer.manifest_canonical(manifest)
```

### What is still not proven

The council as a **rescue**. It has authored a shipping patch (drill two), but it has never
saved a job the plain fixer had already failed — every drill succeeded on attempt 1. Proving
that needs a defect hard enough that attempts 1 and 2 fail honestly.

## Fixes reach production before they reach `main`

This is the part that surprises people, and it is deliberate.

The conductor commits a patch to `momus/fix-<finding_id>-<n>`, the fleet builds an image **from
that branch commit**, and the deploy hand promotes it. So the running service carries the fix
while `main` still carries the defect. From `git_push.py`:

> **Branch only, never main, never force.** The worst thing a stolen credential can do here is
> create a branch nobody merges.

There is a second, independent policy behind that one: the conductor pushes with a **deploy
key**, and this repository's `main` protection has `push_whitelist_deploy_keys` false. The
server refuses that key on `main` whatever the code says.

### The consequence to keep in mind

**Anything that rebuilds from `main` silently reverts the fix.** That is not a hypothetical —
it is how each drill above was reset: `docker compose build praxis` from `main`, no sabotage
required. The window between "the loop repaired it" and "you merged" is a window in which an
ordinary redeploy undoes the repair.

### Merging

```bash
scripts/pull_momus_fixes.sh           # fetch, verify, report. MERGES NOTHING.
scripts/pull_momus_fixes.sh --merge   # merge what it just cleared
scripts/pull_momus_fixes.sh --json    # machine-readable
```

`--merge` clears only branches that touch **nothing but `.momus/*.json`** — append-only
provenance records that change no behaviour. A branch touching code is queued and reported,
because a MOMUS-signed `fixed` verdict proves the finding stopped reproducing, not that the
patch is good.

Two things to know when you run it:

* **Most queued branches must never be merged.** After the drills there were 89 in the queue and
  84 of them were canary attempts — patches to a fixture that must stay broken. Merging them
  would end the canary's usefulness.
* **`git diff main..branch` will look alarming.** A branch created before your recent commits
  shows them as deletions, because a diff compares two states while a merge takes their union.
  Check with a dry run before believing it:

  ```bash
  git merge --no-commit --no-ff momus-fixes/<branch>
  git diff --cached --stat HEAD     # what a merge would ACTUALLY produce
  git merge --abort                 # if you were only looking
  ```

  Done for the PRAXIS merge: the diff claimed 447 deletions across four files; the merge
  produced one file, five lines in, nine out.

### The experimental auto-merge

`SKOPOS_EXPERIMENTAL_AUTO_MERGE=1` on the conductor lets it merge a verified fix itself. It is
off everywhere by default and narrow by construction:

* only a job that reached `DONE` — built, component tests passed, candidate gated, both
  signatures verified, deployed, and confirmed gone **in place**;
* only a branch under the fix prefix, so it cannot be aimed at a person's work;
* `--no-ff`, so the result is one revertible commit naming its finding;
* on conflict it aborts and leaves the default branch untouched;
* never `--force`.

**It is enabled on production and inert.** The server refuses the deploy key:

```
remote: Gitea: Not allowed to push to protected branch main
! [remote rejected]   HEAD -> main (pre-receive hook declined)
```

Making it work takes a deliberate act by the repository owner. Whitelisting that one deploy key
on `main` is the narrow option — one repository, one key, reversible with one toggle in Gitea.
An account token would also work and is much wider: Gitea access tokens are user-scoped, so it
would reach every repository that account owns.

Reversible two ways, always: unset the variable, and `git revert -m 1 <commit>` — the command is
written into the merge commit's own message.

## The cycle, step by step

Every step below is a refusal point. A step that cannot answer stops the cycle rather than
guessing, and the job waits for a person.

| # | Who | What happens | What stops it here |
|---|---|---|---|
| 1 | MOMUS | scans a target on its rota (900 s) and signs a finding with its scanner key | a target with no policy entry is recorded and never dispatched |
| 2 | MOMUS verifier | a **second instance, its own key**, re-runs the probe and cross-checks the contract against the protocol reference | the two readings disagree → `inconclusive`, the finding is not evidence |
| 3 | autopilot | decides whether to dispatch: severity, sightings, cooldown, daily caps | the auditor, payer and conductor are on a permanent denylist |
| 4 | AI-Factory | authors a patch inside a declared scope of 1–3 files | credentials and the loop's own judges are unreadable; a new dependency is refused |
| 5 | conductor | commits it to `momus/fix-<id>-<n>` — never `main`, never `--force` | a non-fast-forward is left for a human, not forced |
| 6 | node agent | builds an image from that commit and runs **the component's own tests** | a failing suite blocks the build before anything is gated |
| 7 | node agent | starts a candidate container, published on no port | a candidate that will not start is itself a verdict on the patch |
| 8 | MOMUS | re-runs the probe against **the candidate**, not the live service | still reproducing → deploy refused |
| 9 | conductor | signs a deploy order carrying MOMUS's fixed-verdict | the agent verifies both signatures and the candidate-vs-live binding |
| 10 | node agent | promotes the image, from its **own local** service allowlist | a service not on that list is refused; the caller cannot widen it |
| 11 | MOMUS | re-runs the probe in place, after the deploy | a regression rolls back on the spot |
| 12 | circuit breaker | counts deploys, rollbacks and consecutive failures | thrashing one service is throttled, not repeated |
| 13 | you | merge the branch | — |

Step 13 is the only human one, and the next section is what it would take to remove it.

## What is left: whitelisting the conductor's key

The auto-merge is built, enabled on production, and inert. Everything up to the push works; the
server refuses the last inch:

```
remote: Gitea: Not allowed to push to protected branch main
! [remote rejected]   HEAD -> main (pre-receive hook declined)
```

That is not a bug to fix in code. It is Gitea's branch protection, and it is the second of the
two independent policies the design asks for — the first being the code's own "branch only,
never main".

**The key to whitelist**, so you are not guessing which one:

```
SHA256:aiTxt4Fy0PAtQXx6f8eCt38EUswyeQmVbPHP2Y9DwJU
skopos-remediation-conductor@oracle-host
```

**Where:** Gitea → the `aicom` repository → Settings → Branches → the `main` protection rule →
enable **Whitelist Deploy Keys**. One repository, one key, one checkbox.

**What changes.** The conductor can then land a fix on `main` itself, and step 13 above
disappears. Nothing else in the loop changes: the code guard still refuses `main` on every other
path, the merge is still `--no-ff`, still aborts on conflict, and still never forces.

**What it costs.** Today a stolen conductor credential can only create a branch nobody merges.
After this it can write to `main` — of **this repository only**, because a deploy key is
per-repository. An account token would also lift the refusal and is much wider: Gitea tokens are
user-scoped and reach every repository that account owns. Prefer the deploy key.

**Rollback.** Uncheck the box, or unset `SKOPOS_EXPERIMENTAL_AUTO_MERGE`, or
`git revert -m 1 <commit>` — the merge commit carries that command in its own message. Any one of
the three is enough.

## Guards added while proving this

Each of these was found by watching the loop rather than by reading it.

**The fixer could read every key in the repository.** The whole monorepo is bind-mounted into
it — the root `.env`, `data/secrets/git-credentials`, a provider key, two JWT signing keys.
Writes had a denylist and a declared scope; reads had a regular expression. Now: refusal by
path, redaction of key material from content, refusal of the auditor's and conductor's own
sources, masks in the container, and an audit that counts what is still visible. Currently zero.

That audit immediately caught the guard being too blunt in the other direction: twenty
"credentials", nineteen of them ARGUS source — `keystore.ts`, `wallet.js`. `wallet.json` is a
wallet; `wallet.ts` is the code that reads one. A guard that refuses source gets widened until
it protects nothing.

**Nothing ran the patched component's own tests.** The single gate was one probe re-run, so a
patch could satisfy the probe, break the suite, and ship. Now a `test` stage in the Dockerfile —
not the default target, so pytest never reaches production — runs the suites covering the
patched modules, with no network, before anything else looks at the build.

Proving that gate turned up something worse: GAIA's attestation tests sign and verify with the
*same* function, so substituting `json.dumps` for `reading_canonical` left all 39 green. The
wire format is pinned to literals now.

**The loop had no independent judge.** `momus.engine.verify.Verifier` was written and never
instantiated, so nothing wrote a confirmed verdict and "the same probe fired twice" became the
whole gate by default rather than by decision. Wiring it up found seven more defects, two of
them dangerous: it read Metis's "my own answer passed my own critic" flag as "the finding is
confirmed" — making any well-formed reply a confirmation, including one whose text said the
finding does *not* reproduce — and a verdict **removed** the sighting requirement, which would
have let one model answer overrule the hub's three-sighting conservatism.

Its first real verdict was also *wrong*: it refuted, at 0.92 confidence, a signature that
genuinely does not verify. Deterministic contract probes are out of a language model's scope
now; they go to a second MOMUS instance with its own key that **re-runs** the probe, and its
answer is cross-checked against the protocol's own conformance reference — a second reading of
the contract, so a probe that is itself wrong is caught rather than confirmed twice.

**Nothing recorded what the model was shown.** The job kept the answer and not the question,
and "the model got it wrong" and "the model was shown the wrong thing" have identical symptoms.
Every exchange now lands in `/data/remediation_exchanges.jsonl`, refusals included.

## Drills and production share one budget

Worth stating plainly because it cost four interruptions in one day: nothing in the loop
distinguishes an exercise from real work. The autopilot's daily caps, its dispatch journal, and
the circuit breaker's per-component deploy throttle all count a drill as production.

The practical risk is not the inconvenience. It is that a real incident on the day after a day
of testing meets guards whose budget is already spent — the protection fails exactly when it is
needed. A `drill` flag on the dispatch record, and counters that keep the two apart, is the fix;
it is not built yet.
