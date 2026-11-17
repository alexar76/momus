"""The `code` target: MOMUS reads a read-only git directory, finds Vulnetix-class bugs, and gates a fix branch."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from momus.engine.remediation import code_area, escalation_for, ticket_component
from momus.findings import Evidence, Finding, Outcome
from momus.targets.base import ProbeContext, SafeHttpClient
from momus.targets.code import CodeTarget, VulnetixClassProbe, focus_from_finding

BAD = '''
def client_key(request):
    return (request.headers.get("x-real-ip") or "").strip() or request.client.host
'''
FIXED = '''
def client_key(request):
    peer = request.client.host if request.client else ""
    if peer_is_local_proxy(peer):
        return (request.headers.get("x-real-ip") or "").strip() or peer
    return peer
'''
STILL_BAD = BAD.replace("client.host", "client.host  # a cosmetic change")


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture()
def repo(tmp_path: Path) -> dict:
    work = tmp_path / "work"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    git(work, "config", "user.email", "t@example.invalid")
    git(work, "config", "user.name", "t")
    (work / "svc").mkdir()
    (work / "svc" / "app.py").write_text(BAD)
    (work / "svc" / "tests").mkdir()
    (work / "svc" / "tests" / "test_app.py").write_text(BAD)  # tests are never scanned
    git(work, "add", "-A")
    git(work, "commit", "-qm", "bad")
    bare = tmp_path / "aicom.git"
    git(tmp_path, "clone", "-q", "--bare", str(work), str(bare))
    return {"work": work, "bare": bare, "url": f"file://{bare}"}


def push_branch(repo: dict, name: str, content: str) -> None:
    work = repo["work"]
    git(work, "checkout", "-q", "-b", name, "main")
    (work / "svc" / "app.py").write_text(content)
    git(work, "commit", "-qam", name)
    git(work, "push", "-q", str(repo["bare"]), f"{name}:{name}")
    git(work, "checkout", "-q", "main")


async def run_probe(target: CodeTarget):
    ctx = ProbeContext(client=SafeHttpClient("http://unused.invalid"))
    try:
        discovery = await target.discover(ctx)
        return discovery, await VulnetixClassProbe().run(target, ctx, discovery)
    finally:
        await ctx.client.aclose()


async def test_the_main_branch_finding_is_signed_with_its_focus(repo):
    discovery, results = await run_probe(CodeTarget("aicom-code", repo["url"]))
    assert len(discovery["commit"]) == 40 and discovery["imageDigest"] == discovery["commit"]
    [r] = results
    assert r.outcome == Outcome.FINDING and r.title == "svc/app.py: VX-FWD-HEADER-TRUST in client_key"
    assert json.loads(r.request_summary) == {"rule": "VX-FWD-HEADER-TRUST", "path": "svc/app.py",
                                             "function": "client_key"}
    assert r.reference_artifacts == ("svc/app.py",) and "peer_is_local_proxy" in r.detail


async def test_a_retest_reads_the_newest_fix_branch_and_only_its_finding(repo):
    focus = {"rule": "VX-FWD-HEADER-TRUST", "path": "svc/app.py", "function": "client_key"}
    push_branch(repo, "momus/fix-f1-1", STILL_BAD)
    push_branch(repo, "momus/fix-f1-2", FIXED)
    base = CodeTarget("aicom-code", repo["url"])
    assert base.candidate_ref("f1") == "refs/heads/momus/fix-f1-2"
    _, results = await run_probe(base.for_candidate("f1", focus))
    assert [r.outcome for r in results] == [Outcome.NO_FINDING]
    # the still-bad attempt reproduces
    _, results = await run_probe(CodeTarget("c", repo["url"], ref="refs/heads/momus/fix-f1-1", focus=focus))
    assert [r.outcome for r in results] == [Outcome.FINDING]
    # main is untouched: the live retest still reproduces
    _, results = await run_probe(base.focused(focus))
    assert [r.outcome for r in results] == [Outcome.FINDING]


async def test_no_fix_branch_yet_is_inconclusive_not_fixed(repo):
    focus = {"rule": "VX-FWD-HEADER-TRUST", "path": "svc/app.py", "function": "client_key"}
    _, results = await run_probe(CodeTarget("aicom-code", repo["url"]).for_candidate("nope", focus))
    assert [r.outcome for r in results] == [Outcome.INCONCLUSIVE]
    assert "unreachable" in results[0].title  # the conductor's gate retries exactly this


def test_only_a_local_git_directory_is_a_code_target():
    for url in ("https://gitea.example/alexar76/aicom.git", "ssh://git@gitea/x.git", "file://host/x.git"):
        with pytest.raises(ValueError):
            CodeTarget("x", url).git_dir
    assert CodeTarget("x", "file:///code/aicom.git").git_dir == "/code/aicom.git"


def test_a_finding_id_cannot_steer_the_branch_lookup(repo):
    assert CodeTarget("x", repo["url"]).candidate_ref("../../main") == ""


def test_code_findings_route_by_source_area():
    def finding(path: str) -> Finding:
        return Finding(target="aicom-code", target_kind="code", probe="code.vulnetix_classes", category="authz",
                       severity="medium", outcome="finding", title=f"{path}: X in f", detail="",
                       evidence=Evidence(request_digest="", response_digest="", reference_artifacts=(path,)))
    assert ticket_component(finding("skopos/skopos/remediation/a2a_ingress.py")) == "code:skopos"
    assert ticket_component(finding("ai-service-mesh/backend/x.py")) == "code:ai-service-mesh"
    assert code_area("code:momus") == "momus" and code_area("praxis") == ""
    for core in ("code:skopos", "code:momus", "code:treasury"):
        assert escalation_for(core) == "human-governance"   # even with no target_kind on the ticket
    assert escalation_for("code:ai-service-mesh", "code") == "auto"


def test_focus_round_trips_through_stored_evidence():
    focus = {"rule": "VX-918-CHECK-THEN-CONNECT", "path": "web/x.py", "function": "f"}
    assert focus_from_finding({"evidence": {"request_snippet": json.dumps(focus)}}) == focus
    assert focus_from_finding({"evidence": {"request_snippet": "GET /x"}}) is None


def test_each_file_and_function_is_its_own_finding_in_the_corpus():
    def code_finding(path: str, function: str) -> Finding:
        focus = json.dumps({"rule": "VX-FWD-HEADER-TRUST", "path": path, "function": function}, sort_keys=True)
        return Finding(target="aicom-code", target_kind="code", probe="code.vulnetix_classes", category="authz",
                       severity="medium", outcome="finding", title=f"{path}: VX-FWD-HEADER-TRUST in {function}",
                       detail="", evidence=Evidence(request_digest="a", response_digest="b", request_snippet=focus))
    a, b = code_finding("svc/a.py", "k"), code_finding("svc/b.py", "k")
    assert a.compute_dedup_key() != b.compute_dedup_key()
    assert a.compute_dedup_key() == code_finding("svc/a.py", "k").compute_dedup_key()   # stable re-sighting
    service = Finding(target="praxis", target_kind="oracle", probe="p", category="integrity", severity="high",
                      outcome="finding", title="t", detail="", evidence=Evidence(request_digest="a", response_digest="b",
                                                                                 request_snippet="x"))
    other = Finding(**{**service.__dict__, "evidence": Evidence(request_digest="c", response_digest="d",
                                                                request_snippet="y")})
    assert service.compute_dedup_key() == other.compute_dedup_key()   # service findings keep their old identity


SILENCED = BAD.replace('    return (request', '    # vx-ok: connect to the address that was checked\n    return (request')


async def test_a_fix_branch_cannot_accept_its_own_finding(repo):
    """2026-11-16, the first live loop: the fixer added only a `# vx-ok:` line and the gate called it fixed."""
    focus = {"rule": "VX-FWD-HEADER-TRUST", "path": "svc/app.py", "function": "client_key"}
    push_branch(repo, "momus/fix-f9-1", SILENCED)
    _, results = await run_probe(CodeTarget("aicom-code", repo["url"]).for_candidate("f9", focus))
    assert [r.outcome for r in results] == [Outcome.FINDING]


async def test_a_mark_already_on_main_still_counts_for_the_branch(repo):
    work = repo["work"]
    (work / "svc" / "app.py").write_text(SILENCED)
    git(work, "commit", "-qam", "accepted on main by a person")
    git(work, "push", "-q", str(repo["bare"]), "main:main")
    focus = {"rule": "VX-FWD-HEADER-TRUST", "path": "svc/app.py", "function": "client_key"}
    push_branch(repo, "momus/fix-f8-1", SILENCED + "\n# unrelated edit\n")
    _, results = await run_probe(CodeTarget("aicom-code", repo["url"]).for_candidate("f8", focus))
    assert [r.outcome for r in results] == [Outcome.NO_FINDING]
