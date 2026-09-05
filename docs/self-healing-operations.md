# Running the self-healing loop — keys, settings, and what redeploys what

> 🌐 **English** · [Русский](self-healing-operations.ru.md) · [Español](self-healing-operations.es.md) · [Français](self-healing-operations.fr.md) · [中文](self-healing-operations.zh.md)

> **Switch it to merge by itself** — one checkbox, with diagrams: [switch-to-auto-merge.md](switch-to-auto-merge.md).

> **Proven end to end** — the practice target, the three drills, and why a fix reaches production before `main`: [proving-the-loop.md](proving-the-loop.md).

> **What stops a bad patch** — every guard an unattended repair passes through, and the incident behind each: [autonomous-repair-guards.md](autonomous-repair-guards.md).

MOMUS finds a bug, the AI-Factory writes a patch, the fleet builds it, MOMUS gates the build, a node
agent ships it, and a regression rolls it back. This page is the operator's side of that: which
service runs where, which environment variable controls which refusal, and — the question that
prompted this page — **how many things you have to redeploy when you change the code.**

## The short answer on redeploys

**One.** Not two factories.

The patch-authoring route (`POST /api/remediation/fix`) is mounted **only** where
`AIFACTORY_REMEDIATION_FIX_ENABLED=1`. On the public instance that variable is unset, so the route
does not exist there at all — not "exists but refuses". That distinction is deliberate:
`web/frontend/next.config.js` rewrites `/api/:path*` to the internal API, so a merely-disabled route
would still be a publicly reachable endpoint answering 403, which is new attack surface bought for
nothing.

So:

| What you changed | What you redeploy |
|---|---|
| `web/backend/api/remediation.py`, `web/backend/services/remediation_fix.py` | the **remediation instance** only |
| `skopos/skopos/remediation/*` | the **conductor** (`skopos-remediation`) |
| `momus/momus/*` | **momus-backend** |
| the node agent's build/deploy code | the **agent** on each fleet host |
| shared `core/`, `llm/` | whichever instances you actually care about — this is already true of every satellite in this monorepo, and is not new with remediation |

The public factory never runs remediation, so remediation changes cannot affect it.

## The two modes

Every component the loop watches is in one of two modes, and the difference is one step at the
end. Both start the same way: MOMUS probes, confirms a finding, signs a remediation ticket, the
conductor drives the Factory to author a patch, and the patch lands on a `momus/fix-…` branch as
a reviewable diff.

**Auto-repair.** A deploy hand for that component builds the branch, MOMUS re-runs the probe
against the candidate, and only a signed `fixed` verdict promotes the image and recreates the
service. Nobody is woken up. This is the mode for a component that has a hand installed and an
image the hand can build.

**Patch-only.** Everything above happens except the last step: the branch is ready and the job
sits waiting. A human reviews the diff and ships it. This is not a degraded mode — it is the
correct one wherever a hand would have nothing to promote, and it is the mode to choose for
anything where you would want to read the patch before it runs.

Which mode a component is in is a property of its deployment, not a setting to remember:

| component | mode | why |
|---|---|---|
| canary | auto-repair | the proving ground for the loop; it exists to be broken and fixed |
| gaia | auto-repair | own compose project, built from this repository |
| hub (production) | auto-repair | its hand reaches the fleet relay; see *Who runs where* |
| oracles | patch-only | built from a separate checkout, so no hand can produce its image |
| MOMUS, Treasury, SKOPOS, the gate | neither | refused in code — see *Containment* |

**Switching a component to patch-only** is a property of its hand, and there are three levers,
in increasing severity:

* `SKOPOS_AGENT_DRY_RUN=1` — the hand verifies the order and prints the command it would run.
  Everything upstream still happens, so this is the mode to use when you want the loop exercised
  without anything moving.
* `SKOPOS_AGENT_SERVICE_ALLOWLIST=` (empty) — the hand refuses every order. Use it to park one
  host without touching the rest of the fleet.
* `systemctl stop skopos-deploy-hand@<component>` — orders queue on the conductor and expire.

**Switching the whole loop to patch-only** is `SKOPOS_REMEDIATION_DRY_RUN=1` on the conductor:
findings, tickets and patches continue, and nothing is ever ordered.

There is no lever that turns patch-only into auto-repair for a component that has no hand. That
is deliberate: a component becomes auto-repairable by having somewhere to be deployed, not by
being marked as such.

## Who runs where

| Role | Service | Bound to |
|---|---|---|
| finds bugs, and is the deploy GATE | `momus-backend` | loopback |
| pays bounties (separate key MOMUS never holds) | `momus-treasury` | loopback |
| orchestrates one remediation job | `skopos-remediation` | loopback |
| authors patches | the remediation instance of the factory | loopback |
| git remote (transport **and** audit trail) | Gitea `alexar76/aicom` | loopback (`:3000` HTTP, `:2222` SSH) |
| builds and ships | the node agent on the target host | outbound only, no listening port |
| the thing to break and fix first | `momus-canary` | loopback |

Nothing here opens an inbound port on a fleet host. The agent polls; it is never called.

## The chain, and why each step exists

```
MOMUS finds ──signed ticket (A2A)──▶ conductor
  ├─ 1. Factory authors a unified DIFF          (never an image; it does not build)
  ├─ 2. conductor commits + pushes momus/fix-<finding_id>
  │        the branch is the transport to the builder AND the artifact a human reviews
  ├─ 3. signed BuildOrder names a COMMIT        (never inline source)
  │        agent: fetch it, refuse any branch outside the host's own prefix list, refuse a commit
  │        that is not that branch's tip, build with the host's OWN recipe, report the DIGEST,
  │        and start <service>-candidate so the gate has something to probe
  ├─ 4. MOMUS gates the CANDIDATE               (pre-promotion, bound to that digest)
  ├─ 5. signed DeployOrder carries the digest
  │        agent: record the running digest, move the compose tag onto the new one, recreate,
  │        health-gate it, and verify the container really IS that digest
  ├─ 6. MOMUS re-tests the LIVE service
  └─ 7. still reproduces → signed RollbackOrder → agent restores the digest it recorded
```

Two omissions used to make this theatre, and both are worth knowing because the symptoms were
misleading:

* **Nothing built an image.** So "deploy" recreated the container from the image already on the
  host, the gate examined the build it was meant to replace, legitimately answered "still
  reproduces", and the escalation blamed the patch.
* **`DeployOrder.image` was read by nothing at all.** The field existed and carried a value.

## Containment: the order says *which*, the host says *what is permitted*

Every constraint below is enforced by the **agent**, from its own local configuration. A caller
cannot widen any of them.

* the agent builds and deploys only services on its own `SKOPOS_AGENT_SERVICE_ALLOWLIST`;
* it builds only from branches matching its own `SKOPOS_AGENT_BRANCH_PREFIXES`;
* it builds only with the Dockerfile and context in its own `SKOPOS_AGENT_BUILD_MAP`;
* it deploys only images **it built itself, for that same service** (checked against its own build
  journal) — so an order naming any other image on the host resolves to nothing;
* it refuses to promote a new image on a verdict that examined the *live* service. `gated` lives
  inside the signed FixVerdict, so it cannot be relabelled on the wire;
* a `RollbackOrder` carries **no image at all** — it names a prior order, and the target comes from
  what the agent recorded as running before that deploy. So the undo path cannot ship anything new,
  which is why it is allowed to skip the MOMUS verdict a forward deploy requires (you roll back
  precisely when that verdict turned out to be wrong).

`main` is protected on the server **and** the conductor refuses to push anywhere outside its branch
prefix. Two independent policies, because one of them being misconfigured must not be enough.

> **Check this before trusting it.** Branch protection on `alexar76/aicom` currently has
> `enable_push=true` with the push whitelist `['alexar76']`. Anything pushing *as that user* can
> therefore reach `main` directly. Push with a per-repository **deploy key**, not a user access token
> (Gitea access tokens are user-scoped: `write:repository` covers every repository the user owns),
> `push_whitelist_deploy_keys` is `false`, so a deploy key cannot reach `main`.
>
> Note on proving it: do NOT test by actually pushing to `main` on a host where a Gitea Actions
> runner is installed — a push to `main` can trigger a deploy workflow. Read the protection config
> instead.

## Settings

### The factory's remediation instance

| Variable | Default | What it does |
|---|---|---|
| `AIFACTORY_REMEDIATION_FIX_ENABLED` | unset | **The master switch.** Unset ⇒ the route is not mounted at all. |
| `AIFACTORY_REMEDIATION_KEY` | unset | Shared secret with the conductor. Required in production; unset in production ⇒ 503, never open. |
| `AIFACTORY_REMEDIATION_MOMUS_PUBKEY` | unset | MOMUS's Ed25519 key. Without it a ticket cannot be verified and every request is refused. |
| `AIFACTORY_REMEDIATION_SCOPE` | canary + hub | JSON `{component: [paths]}`. The **only** files a patch for that component may touch. A model that answers with a path outside it is refused. Hub is scoped to `aimarket-hub/aimarket_hub/unpaid_invoke.py` (the gate MOMUS re-runs); `api.py` is too large. MOMUS / Treasury / the gate are absent. |
| `AIFACTORY_REMEDIATION_LLM_BUDGET_S` | `240` | The route asks for full file contents, so this takes minutes, not seconds. Must stay BELOW the conductor's client timeout. |
| `AIFACTORY_DEMO_READONLY` | — | If `1`, patch authoring is refused: this is the public-demo guard, and a public demo is not where an autonomous patcher belongs. |

### The conductor

| Variable | Default | What it does |
|---|---|---|
| `SKOPOS_REMEDIATION_ENABLED` | `1` | Master switch. `0` ⇒ no deploy order is ever signed. |
| `SKOPOS_REMEDIATION_DRY_RUN` | `0` | `1` ⇒ the chain runs and signs nothing that ships. Honest about it: a dry-run job closes saying nothing was deployed. Live (`0`) is the default for canary + hub. |
| `SKOPOS_FACTORY_URL` | unset | Unset **while live** is a configuration fault, not a fallback — it used to synthesize a fake patch. |
| `SKOPOS_MOMUS_PUBKEY` | unset | Required outside dry-run: an unverifiable ticket is refused. |
| `SKOPOS_GIT_REPO_URL` / `SKOPOS_GIT_SSH_KEY` | unset | The fix-branch remote and its credential (a deploy key). |
| `SKOPOS_AGENT_TOKEN` | unset | The enrolment token the deploy hand presents. Without it the conductor hands out no orders outside dry-run (fail-closed), so the hand polls forever and gets 503. |
| `SKOPOS_FIX_BRANCH_PREFIX` | `momus/fix-` | Also the prefix the conductor refuses to push outside of. |
| `SKOPOS_DEPLOY_RESULT_TIMEOUT_S` | `420` | How long to wait for the agent's report. Must exceed its poll interval + compose timeout + health wait. |
| `SKOPOS_MAX_DEPLOYS_PER_DAY` | `6` | Throttle. Reached ⇒ refused, breaker NOT tripped. |
| `SKOPOS_MAX_DEPLOYS_PER_COMPONENT_PER_DAY` | `2` | Repeatedly redeploying one service is thrashing, not remediation. |
| `SKOPOS_MAX_ROLLBACKS` | `2` | **The signal that matters.** Two undos in the window ⇒ breaker trips. |
| `SKOPOS_MAX_ROLLBACK_RATE` | `0.34` | With `SKOPOS_BREAKER_MIN_SAMPLE` (`5`), because 1-of-1 is not a 100% failure rate. |
| `SKOPOS_MAX_CONSECUTIVE_FAILURES` | `3` | Hand a component that cannot be fixed to a human. |
| `SKOPOS_OPERATOR_TOKEN` | unset | Required to clear a tripped breaker. Unset ⇒ nobody can, which is the safe direction. |

### The node agent

| Variable | Default | What it does |
|---|---|---|
| `SKOPOS_AGENT_DRY_RUN` | `0` | `1` ⇒ validates and prints the command, executes nothing. Live (`0`) is the default. |
| `SKOPOS_AGENT_SERVICE_ALLOWLIST` | `canary,hub` | Comma-separated. Unset ⇒ canary + hub (and their compose aliases). Empty ⇒ the agent can touch nothing. MOMUS / Treasury stay off this list. |
| `SKOPOS_AGENT_BRANCH_PREFIXES` | `momus/fix-` | Local. A build from `main` would be a build of whatever anyone last merged. |
| `SKOPOS_AGENT_BUILD_MAP` | canary + hub recipes | JSON `{service: {dockerfile, context, image_ref, network, compose_service}}` overlays the built-in recipes. Built-in: `canary` → compose `momus-canary`; `hub` → compose `hub`, Dockerfile `aimarket-hub/Dockerfile`. No recipe ⇒ refuses to build that service. **`compose_service` is required wherever the component name and the compose service name differ.** |
| `SKOPOS_AGENT_REPO_URL` | unset | Where source may come from. Never read off an order. |
| `SKOPOS_AGENT_HEALTH_WAIT_S` | `20` | How long a container gets to prove it is not crash-looping. `compose up` exiting 0 is not a verdict. |

## Watching it, and stopping it

* `GET /remediation/health` — the numbers, plus the breaker's state and thresholds.
* `GET /metrics` — Prometheus. The one to alert on is **`skopos_remediation_rollback_rate`**: undos
  per shipped patch, i.e. the rate at which the gate's verdict and reality disagree. A patch the gate
  refuses costs nothing; a patch that shipped and had to be undone is the dangerous shape.
* `GET /api/remediation/stats` — the digest LOGOS reads. Do not rename its keys.
* `POST /remediation/breaker/clear` with `x-skopos-operator` — the **only** way to re-arm a tripped
  breaker. Nothing in the code clears it: a breaker that reset on restart would be defeated by the
  crash-loop it exists to interrupt, and "it recovered on its own" is indistinguishable from "nobody
  found out". A tripped breaker survives a restart, and an unreadable breaker file fails closed.

## Enabling it, in the order that is defensible

1. Set the factory's `AIFACTORY_REMEDIATION_*` on the **private** instance and confirm
   `GET /api/remediation/fix/status` shows `enabled: true` and the scope you expect.
2. Give the conductor its git credential and **prove `main` refuses a push** before trusting it.
3. Run the node agent. Defaults are live: `SKOPOS_AGENT_DRY_RUN=0` and
   `SKOPOS_AGENT_SERVICE_ALLOWLIST=canary,hub`. MOMUS / Treasury stay off that list.
4. Confirm `/remediation/health` shows dry-run off and the agent is claiming orders.
5. Break the canary on purpose, watch the loop heal and redeploy it, and read the branch it pushed.
6. Hub is already on the same path. A `fixed` verdict still does not merge to `main`.
7. To park: `SKOPOS_AGENT_DRY_RUN=1` and `SKOPOS_REMEDIATION_DRY_RUN=1`, or empty the allowlist.

Findings against the security core (MOMUS, the Treasury, the gate itself) never take this path at
all: `escalation_for` routes them to human governance plus an independently-operated verifier,
because an auditor that fixes itself has certified its own work.
