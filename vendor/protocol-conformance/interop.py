#!/usr/bin/env python3
"""Interop page: who, outside this project, speaks the protocol — measured, not claimed.

    python3 conformance/interop.py --out DIR [--hub https://modelmarket.dev]
                                   [--histor https://histor.modelmarket.dev]

Writes DIR/interop.json and DIR/index.html. Three counters, each one a number this project
cannot raise by turning up its own traffic, because everything at a host listed in
own-operators.txt is subtracted first:

1. Peers operated by others that pass the live conformance checks of run.py — the peers the
   reference hub knows (``/ai-market/v2/federation/peers``: admitted and pending).
2. Witnesses operated by others whose cosignature is on HISTOR's checkpoint
   (``/checkpoint``, c2sp.org/tlog-cosignature lines other than the log's own).
3. AWR documents issued by keys others control: reported as not measurable, with the reason,
   until there is a public place where such documents arrive.

Per peer, the page lists every live check and its result, so a reader can see why a peer did
or did not count. Nothing here is a certification (GOVERNANCE.md § Conformance): a peer that
passes "interoperates with the reference hub on the discovery surface", nothing more.

Exit status 0 when the page was written, 1 when the reference hub could not be read at all.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import html
import io
import importlib.util
import json
import pathlib
import sys
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent


def _load_runner():
    spec = importlib.util.spec_from_file_location("aimarket_conformance_run", HERE / "run.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def load_own(path: pathlib.Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.append(line)
    return out


def is_own(value: str, own: list[str]) -> bool:
    text = value.strip().lower()
    host = urllib.parse.urlsplit(text if "://" in text else "https://" + text).hostname or text
    for entry in own:
        if "/" in entry:
            if text.split("://", 1)[-1].rstrip("/") == entry.rstrip("/"):
                return True
            continue
        if host == entry or host.endswith("." + entry):
            return True
    return False


def get_text(url: str, timeout: float = 20.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "AIMarketInterop/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


# Checks that only a hub can pass: a provider publishes a catalogue and has no peers to list.
HUB_ONLY = ("GET /ai-market/v2/federation/peers", "peers endpoint returns a peers array",
            "§2.4 pending queue exposed separately", "§2.4(1) no pending peer is marked trusted")


def check_peer(run, base: str) -> dict:
    run.results.clear()
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            run.check_live_hub(base)
        except Exception as exc:  # a peer that breaks the runner is a failed peer, not a failed page
            run.record(False, "runner", f"{type(exc).__name__}: {exc}"[:120])
    checks = [{"ok": bool(ok), "name": name, "detail": detail} for ok, name, detail in run.results]
    names = {c["name"] for c in checks if c["ok"]}
    is_hub = "GET /ai-market/v2/federation/peers" in names
    if not is_hub:
        for c in checks:
            if c["name"] in HUB_ONLY and not c["ok"]:
                c["ok"], c["applicable"] = True, False
                c["detail"] = "not applicable: a provider, not a hub (" + c["detail"] + ")"
        checks = [c for c in checks if c.get("applicable", True)]
    failed = [c for c in checks if not c["ok"]]
    return {
        "url": base,
        "kind": "hub" if is_hub else "provider",
        "passed": len(checks) - len(failed),
        "total": len(checks),
        "allPassed": bool(checks) and not failed,
        "draftNames": "GET /.well-known/agent-marketplace (draft name)" in names,
        "checks": checks,
    }


def witness_lines(histor: str) -> list[dict]:
    note = get_text(f"{histor}/checkpoint")
    text, _, sigs = note.rpartition("\n\n")
    out = []
    origin = text.split("\n", 1)[0]
    for line in sigs.splitlines():
        if not line.startswith("— "):
            continue
        name = line[2:].split(" ", 1)[0]
        if name != origin:
            out.append({"name": name})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--hub", default="https://modelmarket.dev")
    ap.add_argument("--histor", default="https://histor.modelmarket.dev")
    ap.add_argument("--own", default=str(HERE / "own-operators.txt"))
    args = ap.parse_args(argv)

    run = _load_runner()
    own = load_own(pathlib.Path(args.own))
    hub = args.hub.rstrip("/")
    try:
        status, peers_doc = run.fetch(f"{hub}/ai-market/v2/federation/peers")
    except Exception as exc:
        print(f"cannot read {hub}: {exc}", file=sys.stderr)
        return 1
    urls = []
    for group in ("peers", "pending"):
        for p in peers_doc.get(group) or []:
            url = (p.get("url") or p.get("hub_url") or "").rstrip("/") if isinstance(p, dict) else ""
            if url and url not in urls:
                urls.append(url)
    urls = [hub] + [u for u in urls if u != hub]

    peers = []
    for url in urls:
        row = check_peer(run, url)
        row["operator"] = "this project" if is_own(url, own) else "outside"
        peers.append(row)

    try:
        cosigners = witness_lines(args.histor.rstrip("/"))
        for w in cosigners:
            w["operator"] = "this project" if is_own(w["name"], own) else "outside"
        witness_error = ""
    except Exception as exc:
        cosigners, witness_error = [], f"{type(exc).__name__}: {exc}"[:160]

    outside_peers = [p for p in peers if p["operator"] == "outside"]
    counters = {
        "outsidePeersPassing": sum(1 for p in outside_peers if p["allPassed"]),
        "outsideProvidersPassing": sum(1 for p in outside_peers if p["allPassed"] and p["kind"] == "provider"),
        "outsideHubsPassing": sum(1 for p in outside_peers if p["allPassed"] and p["kind"] == "hub"),
        "outsidePeersKnown": len(outside_peers),
        "outsideWitnesses": sum(1 for w in cosigners if w["operator"] == "outside"),
        "outsideAwrIssuers": None,
    }
    doc = {
        "generatedAt": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "referenceHub": hub,
        "histor": args.histor,
        "ownOperators": own,
        "counters": counters,
        "notes": {
            "outsideAwrIssuers": "not measurable yet: there is no public place where AWR documents issued by "
                                 "others arrive (the HISTOR receipts log admits only listed issuers, all of them "
                                 "this project's). Counted from the day such an intake exists.",
            "witnessError": witness_error,
        },
        "peers": peers,
        "witnesses": cosigners,
    }
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "interop.json.tmp").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    (out / "interop.json.tmp").replace(out / "interop.json")
    (out / "index.html.tmp").write_text(render(doc), encoding="utf-8")
    (out / "index.html.tmp").replace(out / "index.html")
    print(f"wrote {out}/index.html: {len(peers)} peers, counters {counters}")
    return 0


def render(doc: dict) -> str:
    e = html.escape
    c = doc["counters"]

    def counter(value, label, note=""):
        shown = "—" if value is None else str(value)
        return (f'<div class="c"><div class="n">{e(shown)}</div><div class="l">{e(label)}</div>'
                + (f'<div class="note">{e(note)}</div>' if note else "") + "</div>")

    rows = []
    for p in doc["peers"]:
        failed = [ch for ch in p["checks"] if not ch["ok"]]
        detail = "; ".join(f'{ch["name"]}: {ch["detail"]}' if ch["detail"] else ch["name"] for ch in failed)
        rows.append(
            f'<tr class="{ "ok" if p["allPassed"] else "bad" }"><td><a href="{e(p["url"])}">{e(p["url"])}</a></td>'
            f'<td>{e(p["operator"])}</td><td>{e(p["kind"])}</td><td>{p["passed"]}/{p["total"]}</td>'
            f'<td>{"yes" if p["draftNames"] else "no"}</td><td class="d">{e(detail) or "all passed"}</td></tr>')
    wit = "".join(f'<li>{e(w["name"])} — {e(w["operator"])}</li>' for w in doc["witnesses"]) or "<li>none yet</li>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AIMarket Protocol interop</title>
<meta name="description" content="Who outside this project speaks the AIMarket Protocol, measured against the reference hub.">
<style>
:root{{--bg:#fff;--fg:#14181f;--mut:#5b6573;--ok:#0b7a3e;--bad:#a4282b;--line:#e3e6ea;--card:#f6f7f9}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1216;--fg:#e8ebef;--mut:#9aa4b2;--ok:#4cc38a;--bad:#ff7b72;--line:#262b33;--card:#171b21}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px}} h1{{font-size:22px;margin:0 0 4px}} p{{color:var(--mut);margin:4px 0 16px}}
.cs{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:16px 0 24px}}
.c{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}} .n{{font-size:32px;font-weight:650}}
.l{{color:var(--mut)}} .note{{color:var(--mut);font-size:12px;margin-top:6px}}
.t{{overflow-x:auto}} table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
tr.ok td:first-child{{border-left:3px solid var(--ok)}} tr.bad td:first-child{{border-left:3px solid var(--bad)}} td.d{{color:var(--mut);max-width:420px}}
a{{color:inherit}} code{{font-size:12px}}
</style></head><body><main>
<h1>AIMarket Protocol — interop</h1>
<p>Generated {e(doc["generatedAt"])} (hourly) by <code>aimarket-protocol/conformance/interop.py</code> against <a href="{e(doc["referenceHub"])}">{e(doc["referenceHub"])}</a>.
A peer counts as "outside" only if its host is not in <code>own-operators.txt</code>. Passing means
"interoperates with the reference hub on the discovery surface", not certification, and says nothing about whose software the peer runs. Hub-only checks are left out for providers. Raw data: <a href="interop.json">interop.json</a>.</p>
<div class="cs">
{counter(c["outsideHubsPassing"], "hubs run by others that pass every live check")}
{counter(c["outsideProvidersPassing"], f'providers run by others whose signed catalogue verifies (of {c["outsidePeersKnown"]} outside peers known)')}
{counter(c["outsideWitnesses"], "witnesses run by others that co-signed HISTOR")}
{counter(c["outsideAwrIssuers"], "AWR issuers outside this project", doc["notes"]["outsideAwrIssuers"])}
</div>
<h2>Peers the reference hub knows</h2>
<div class="t"><table><thead><tr><th>Peer</th><th>Operator</th><th>Kind</th><th>Checks</th><th>Draft names</th><th>What failed</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
<h2>Cosignatures on HISTOR's checkpoint</h2><ul>{wit}</ul>
</main></body></html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
