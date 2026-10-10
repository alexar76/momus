# What stops a bad patch — the guards an unattended repair passes through

> 🌐 **English** · [Русский](autonomous-repair-guards.ru.md) · [Español](autonomous-repair-guards.es.md) · [Français](autonomous-repair-guards.fr.md) · [中文](autonomous-repair-guards.zh.md)

> **Switch it to merge by itself** — one checkbox, with diagrams: [switch-to-auto-merge.md](switch-to-auto-merge.md).

> **Proven end to end** — the practice target, the three drills, and why a fix reaches production before `main`: [proving-the-loop.md](proving-the-loop.md).

On **2026-08-29** the loop closed a cycle with nobody in it: the autopilot dispatched on its own
schedule at 13:58:33 and MOMUS confirmed the fix in place at 14:02:15 — three minutes forty-two
seconds, one real container replaced, verified from outside the loop by an over-ceiling unpaid
call answering `402` instead of `200`.

Getting there took sixteen separate stops. None of them was visible from reading the code; every
one appeared because a run halted. This page is what each of those became — the guards a patch
now passes through, in the order it meets them, and the incident behind each. Read it as the
answer to two questions an operator will eventually ask: *what stops a bad patch*, and *why did
my repair stop*.

The through-line: **nothing ships that has not been shown to fix the thing.** In eight
consecutive runs the loop never once promoted a patch that did not pass its own gate. Everything
below is either that rule, or a way of not wasting a run before reaching it.

## Before a ticket is even spent

| Guard | What it refuses | Why it exists |
|---|---|---|
| **Dispatch policy** | a component with no entry, or a severity below it | Omission is a default, and a default is what a widened config overrides unnoticed. Denied components (the auditor, the payer, the conductor) are refused by name, not by absence. |
| **Freshness** (`AUTOPILOT_STALE_AFTER_S`) | a finding the latest scans no longer reproduce | `seen_count` is cumulative and never falls, so a bug fixed weeks ago still looks like evidence for ever. A finding nobody reproduces any more is a closed bug with a long memory. |
| **Cooldown**, lifted for terminal jobs | piling tickets onto work in flight | The cooldown protects work. A job that escalated has none, and a finding still reproducing after that is exactly the case worth another go. Repeats stay bounded by the daily caps, which are the right instrument for "this keeps failing". |
| **Refund** (`AUTOPILOT_RECONCILE_WINDOW_S`) | spending the day's budget on a ticket nobody acted on | MOMUS answers `200` and the A2A ingress answers "working" the moment it accepts, because the job runs in the background — the reply cannot say what became of it. The autopilot asks the conductor, in a window, whether work actually started. Asked open-endedly, a ticket someone sends hours later retroactively justifies a dead one. An unreachable conductor never refunds: over-refunding turns a cap into no cap. |

## While the patch is being written

| Guard | What it refuses | Why it exists |
|---|---|---|
| **Conflict of interest** | a patch touching `momus/momus/`, `treasury/`, `skopos/`, or the gate itself | A loop that can patch what decides a finding is real can decide it is not. Enforced in code against both the scope map and the model's answer. |
| **Truncation** | an answer cut off at the output limit | `finish_reason` was in the provider response and unread, so a file whose last triple-quoted string never closed was committed, built and launched. It is refused **even when the surviving fragment parses**: truncation is a property of the answer, not of the fragment. |
| **Syntax** | a patch that does not compile | `ast.parse` answers in milliseconds what a container start answered in ninety seconds — and answered as "the candidate did not start", an infrastructure-shaped message for a truncated file. |
| **Dependencies** | an import the component's build does not declare | A Docker build only copies source, so a patch that adds a library builds cleanly and dies at import. The guard reads the component's Dockerfile / requirements / pyproject: "not imported by the files I may patch" is not "not installed". |
| **No-op** | a patch that changes nothing | Reporting success there would push an empty branch and have MOMUS gate the unpatched build. |

Every refusal above **travels into the next attempt.** At temperature 0 the same prompt returns
the same patch, so a retry that does not know why the last one failed is a repeat, not a retry —
measured: three identical rejected diffs in eight seconds.

## While it ships

| Guard | What it refuses | Why it exists |
|---|---|---|
| **A free branch, never a force** | overwriting a fix branch | A re-opened job resets its attempt budget by design, so `attempt` cannot be a unique name. The name is chosen free against a freshly fetched mirror; forcing stays refused, because a diverged fix branch may be one a human is reading. |
| **The pre-promotion gate** | promoting a build MOMUS has not confirmed | The probe is re-run **against the candidate**, so a "fixed" verdict is about the thing that is about to ship rather than about the unpatched service still running. |
| **Gate readiness** (`SKOPOS_GATE_RETRIES`) | calling a still-starting service "unreachable" | RUNNING is not LISTENING: the agent reports a build the moment the container is up. Only *unreachable* is re-asked — a refusal will refuse identically. |
| **An inconclusive gate is not a verdict** | blaming the patch for a gate that could not run | Another Factory attempt cannot fix a gate that will not run; looping would burn the budget and then escalate blaming the fix. |
| **The agent deploys only what it built** | a signed order naming an image this agent did not produce | Authority is split on purpose: the conductor publishes an order and cannot execute it; the agent executes and cannot invent one. |
| **Rollback on regression** | leaving a bad promotion in place | The post-deploy re-test runs **after** the agent reports, not before — a re-test that races the poll interval describes the build you were trying to replace. |

## When it still cannot fix it

Three attempts, and then a human. Two levers decide what those attempts are worth:

* **Escalate the model, not the counter** (`AIFACTORY_REMEDIATION_ESCALATION_MODEL`). From
  attempt 2 the repair round uses the named model. Unset means the router's own choice — three
  attempts with one model that cannot solve a problem are three failures of the same kind and
  no new information.
* **Give it the contract, not a description of it.** A probe that says "your signature does not
  verify" without saying *what* is signed is asking someone to reimplement an interop contract
  from prose, and every attempt reimplemented it differently. Probes state their acceptance
  criterion, and where a shared library defines the contract the service imports it — a second
  copy drifts the day the first one gains a field.

## What a human still owns

* Findings against the security core — the auditor, the Treasury, the gate — never take this
  path at all. An auditor that fixes itself has certified its own work.
* Merging a fix branch to `main`. A `fixed` verdict ships an image; it does not merge code.
* What a component's image contains. The loop may fix code inside an image and may never add a
  dependency of its own: that is a supply-chain decision.
* Clearing a tripped breaker. Nothing in the code clears it — a breaker that reset on restart
  would be defeated by the crash-loop it exists to interrupt.

## Settings this page introduced

| Variable | Default | What it does |
|---|---|---|
| `AUTOPILOT_CONDUCTOR_URL` | `http://127.0.0.1:9402` | Read-only, and only to answer one question: did the ticket we sent start any work? |
| `AUTOPILOT_RECONCILE_WINDOW_S` | `600` | How long a dispatch has to show up as work before it is called absorbed and refunded. |
| `AUTOPILOT_STALE_AFTER_S` | `2 ×` the scan interval | Older than this without reproducing, and a finding is not a live defect. `0` disables the check. |
| `SKOPOS_GATE_RETRIES` / `SKOPOS_GATE_RETRY_DELAY_S` | `6` / `5` | Half a minute of startup slack for a candidate the agent has already reported as running. |
| `AIFACTORY_REMEDIATION_ESCALATION_MODEL` | unset | The model to use from attempt 2 onward. Which model to spend on is an operator's decision. |

## The lesson worth keeping

Three of the sixteen stops were not defects in the loop but defects in how it was **checked**:
a fix that was supposed to deliver a contract to the model looked done three times and was not,
until the actual prompt was rendered at the receiver. A build check ran against the wrong
checkout. A watcher counted an old journal entry as a fresh one.

**Verify a delivery at the receiver, never at the sender.** Everything upstream of that can look
correct while nothing arrives.
