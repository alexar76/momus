"""The `code` target: MOMUS reads the ecosystem's own source, not only its running services.

Why: from August to November 2026 MOMUS probed six live endpoints and found nothing real, while an outside audit
(Vulnetix) found a dozen bugs by reading the code — services open without a key outside production, checked-then-
connected-by-name SSRF, client addresses taken from forwarding headers without a proxy check, ssh without host keys.
None of those classes is visible to a black-box probe of the economy contract. This target makes them MOMUS's job:
the same rules the push gate runs (momus.codescan.vulnetix_classes) over a commit of the repository, every finding
signed and recorded like any other, and fixed through the same remediation loop.

Allowlisted like every target (MOMUS_EXTRA_TARGETS="aicom-code|file:///code/aicom.git|code"): the URL is a LOCAL git
directory the operator mounts read-only (on admin-vps, Gitea's own bare repository). MOMUS never fetches, never
holds a credential, never writes to it, and runs nothing from it — it reads blobs with `git archive` and parses them.

The deploy gate works per finding. A probe of the whole tree always finds *something* while any bug is open, so
"still reproduces" would never clear. A retest is therefore FOCUSED — rule, file and function of the one finding —
and runs against the CANDIDATE: the newest `momus/fix-<finding_id>-<n>` branch the conductor pushed for it.
"""

from __future__ import annotations

import asyncio
import io
import json
import re
import os
import subprocess
import tarfile
import tempfile
from typing import Any
from urllib.parse import unquote, urlsplit

from momus.codescan import vulnetix_classes as vx
from momus.findings import Outcome, Severity
from momus.targets.base import ProbeContext, ProbeResult, ProbeStrategy, Target

#: Severity and attack class per rule. The classes are the bandit's arm names (category|target_kind).
RULES: dict[str, tuple[Severity, str]] = {
    "VX-306-OPEN-WITHOUT-KEY": (Severity.HIGH, "authz"),
    "VX-918-UNPINNED-RETURN": (Severity.HIGH, "ssrf"),
    "VX-918-CHECK-THEN-CONNECT": (Severity.MEDIUM, "ssrf"),
    "VX-FWD-HEADER-TRUST": (Severity.MEDIUM, "authz"),
    "VX-SSH-NO-HOSTKEY": (Severity.MEDIUM, "integrity"),
    # 2026-11-16, from published outside advisories (artifacts/momus-outside-cves-2026-11-16):
    "VX-295-TLS-OFF": (Severity.MEDIUM, "integrity"),
    "VX-918-FETCH-UNCHECKED": (Severity.HIGH, "ssrf"),
    "VX-918-REDIRECT-AFTER-CHECK": (Severity.MEDIUM, "ssrf"),
    "VX-306-ROUTE-NO-AUTH": (Severity.MEDIUM, "authz"),
}

#: How a fix is recognised: the shape each rule accepts. Shown to the fixer as the acceptance criterion.
FIX_SHAPE = {
    "VX-306-OPEN-WITHOUT-KEY": "with no key configured, admit local callers only (loopback peer, loopback Host, no "
                               "forwarding headers) or refuse; never return 'allowed' for everyone",
    "VX-918-UNPINNED-RETURN": "pin every scheme: resolve once, check every address, connect to the checked IP and "
                              "send the name as Host and TLS SNI (httpx extension sni_hostname)",
    "VX-918-CHECK-THEN-CONNECT": "connect to the address that was checked (pin it), not to the name a second "
                                 "resolution may answer differently",
    "VX-FWD-HEADER-TRUST": "read X-Real-IP / X-Forwarded-For only when the socket peer is a trusted proxy "
                           "(`if peer in trusted_proxies:` / `peer_is_local_proxy(peer)`), else use the peer",
    "VX-SSH-NO-HOSTKEY": "StrictHostKeyChecking=accept-new with a pinned UserKnownHostsFile",
    "VX-295-TLS-OFF": "leave certificate checking on (pass a CA bundle for a private CA); relax it only under an "
                      "`if` that limits it to a loopback peer, or where the code compares the certificate itself",
    "VX-918-FETCH-UNCHECKED": "check the caller's URL before the request (scheme, resolve once, refuse private/"
                              "loopback/link-local) and connect to the checked address",
    "VX-918-REDIRECT-AFTER-CHECK": "fetch with redirects off (allow_redirects=False / follow_redirects=False) and "
                                   "check every Location before following it",
    "VX-306-ROUTE-NO-AUTH": "require a key, token or session on every state-changing route (a FastAPI dependency, "
                            "a Flask before_request), or bind the app to loopback only",
}

_FIX_BRANCH = "refs/heads/momus/fix-{fid}-"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_CACHE_MAX = 4


_GITCONFIG: str | None = None


def _git_env() -> dict[str, str]:
    """The repository belongs to Gitea's user and is mounted read-only; git refuses to read a repository owned by
    someone else unless safe.directory says the operator meant it — and honours that only from a GLOBAL config
    (not `-c`, not GIT_CONFIG_COUNT). So a private global config with exactly that setting. Nothing here writes."""
    global _GITCONFIG
    if _GITCONFIG is None:
        path = os.path.join(tempfile.mkdtemp(prefix="momus-git-"), "gitconfig")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("[safe]\n\tdirectory = *\n")
        _GITCONFIG = path
    return {**os.environ, "GIT_CONFIG_GLOBAL": _GITCONFIG, "GIT_CONFIG_NOSYSTEM": "1"}


def _focus_of(result_request: str) -> dict[str, str] | None:
    try:
        focus = json.loads(result_request)
    except (TypeError, ValueError):
        return None
    return focus if isinstance(focus, dict) and {"rule", "path", "function"} <= focus.keys() else None


class CodeTarget(Target):
    kind = "code"

    _cache: dict[str, list[vx.Finding]] = {}   # commit sha -> findings (a commit never changes)

    def __init__(self, name: str, base_url: str, *, transport: Any = None, ref: str = "refs/heads/main",
                 focus: dict[str, str] | None = None, base_ref: str = "") -> None:
        super().__init__(name, base_url, transport=transport)
        self.ref = ref
        self.focus = focus
        #: For a candidate (fix branch): the branch it is judged against. Only acceptance marks already present
        #: there count, so a fix cannot silence the rule it is meant to satisfy.
        self.base_ref = base_ref

    # --- the repository, read-only -------------------------------------------------------------------------------
    @property
    def git_dir(self) -> str:
        parts = urlsplit(self.base_url)
        if parts.scheme != "file" or parts.netloc not in ("", "localhost"):
            raise ValueError("a code target is a local git directory: file:///path/repo.git")
        return unquote(parts.path)

    def _git(self, *args: str, binary: bool = False, timeout: float = 120.0):
        out = subprocess.run(["git", "--git-dir", self.git_dir, *args], env=_git_env(),
                             capture_output=True, timeout=timeout, check=True)
        return out.stdout if binary else out.stdout.decode("utf-8", "replace")

    def resolve(self, ref: str) -> str:
        return self._git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").strip()

    def candidate_ref(self, finding_id: str) -> str:
        """The newest fix branch the conductor pushed for this finding (by attempt number), or ""."""
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", finding_id or ""):
            return ""
        prefix = _FIX_BRANCH.format(fid=finding_id)
        refs = self._git("for-each-ref", "--format=%(refname)", prefix.rstrip("-") + "*").split()
        numbered = []
        for ref in refs:
            tail = ref[len(prefix):] if ref.startswith(prefix) else ""
            numbered.append((int(tail) if tail.isdigit() else 0, ref))
        return max(numbered)[1] if numbered else ""

    def for_candidate(self, finding_id: str, focus: dict[str, str] | None) -> "CodeTarget":
        ref = self.candidate_ref(finding_id) or f"refs/heads/momus/fix-{finding_id}-missing"
        return CodeTarget(f"{self.name}-candidate", self.base_url, ref=ref, focus=focus, base_ref=self.ref)

    def focused(self, focus: dict[str, str] | None) -> "CodeTarget":
        return CodeTarget(self.name, self.base_url, ref=self.ref, focus=focus)

    def scan_commit(self, sha: str) -> list[vx.Finding]:
        """Every Vulnetix-class finding at a commit (or only the focused file, for a retest)."""
        if self.focus:
            path = self.focus["path"]
            try:
                blob = self._git("show", f"{sha}:{path}", binary=True)
            except subprocess.CalledProcessError:
                return []   # the file is gone at this commit: nothing of it can reproduce
            honored = None
            if self.base_ref:
                try:
                    base = self._git("show", f"{self.base_ref}:{path}", binary=True).decode("utf-8", "replace")
                except subprocess.CalledProcessError:
                    base = ""
                honored = vx.ok_marks(base)
            return vx.scan_file(path, blob.decode("utf-8", "replace"), honored)
        if sha in self._cache:
            return self._cache[sha]
        data = self._git("archive", "--format=tar", sha, binary=True, timeout=300.0)
        items = []
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            for m in tar:
                if m.isfile() and not vx.EXCLUDE.search(m.name) and (m.name.endswith(".py") or vx.SSH_FILE.search(m.name)):
                    fh = tar.extractfile(m)
                    if fh is not None:
                        items.append((m.name, fh.read().decode("utf-8", "replace")))
        found = vx.scan(items)
        if len(self._cache) >= _CACHE_MAX:
            self._cache.pop(next(iter(self._cache)))
        self._cache[sha] = found
        return found

    async def discover(self, ctx: ProbeContext) -> dict[str, Any]:
        _ = ctx
        try:
            sha = await asyncio.to_thread(self.resolve, self.ref)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return {"error": f"{type(exc).__name__}: {exc}"[:300]}
        if not _SHA.match(sha):
            return {"error": f"{self.ref} does not resolve in the code mirror"}
        # `imageDigest` is what a FixVerdict records as the artifact: for code, the commit that was judged.
        return {"ref": self.ref, "commit": sha, "imageDigest": sha}

    def strategies(self) -> list[ProbeStrategy]:
        return [VulnetixClassProbe()]


class VulnetixClassProbe(ProbeStrategy):
    """The rules the push gate runs, over a whole commit — or one finding's file and function, for a retest."""

    probe_id = "code.vulnetix_classes"
    category = "authz"

    async def run(self, target: Target, ctx: ProbeContext, discovery: dict[str, Any]) -> list[ProbeResult]:
        _ = ctx
        assert isinstance(target, CodeTarget)
        sha = discovery.get("commit")
        if not sha:
            return [ProbeResult(self.probe_id, self.category, Outcome.INCONCLUSIVE, Severity.INFO,
                                f"{target.name}: target unreachable — {discovery.get('error') or 'no commit'}",
                                str(discovery.get("error") or ""))]
        try:
            found = await asyncio.to_thread(target.scan_commit, sha)
        except (OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
            return [ProbeResult(self.probe_id, self.category, Outcome.INCONCLUSIVE, Severity.INFO,
                                f"{target.name}: target unreachable — could not read {sha[:12]}",
                                f"{type(exc).__name__}: {exc}"[:300])]
        if target.focus:
            f = target.focus
            found = [x for x in found if x.rule == f["rule"] and x.path == f["path"] and x.function == f["function"]]
        results = [self._result(target, sha, x) for x in found]
        # One result per (rule, file, function): two lines of one function are one defect for a fixer.
        unique = {r.title: r for r in results}
        if unique:
            return list(unique.values())
        scope = (f"{target.focus['rule']} in {target.focus['path']}::{target.focus['function']}" if target.focus
                 else "the whole tree")
        return [ProbeResult(self.probe_id, self.category, Outcome.NO_FINDING, Severity.INFO,
                            f"{target.name}: no Vulnetix-class finding at {sha[:12]} ({scope})", "")]

    def _result(self, target: CodeTarget, sha: str, x: vx.Finding) -> ProbeResult:
        severity, category = RULES.get(x.rule, (Severity.MEDIUM, "authz"))
        focus = {"rule": x.rule, "path": x.path, "function": x.function}
        return ProbeResult(
            probe=self.probe_id, category=category, outcome=Outcome.FINDING, severity=severity,
            # Stable across commits (no line number, no sha): the corpus dedups on it and counts sightings.
            title=f"{x.path}: {x.rule} in {x.function}",
            detail=(f"{x.message}.\n\nAt commit {sha[:12]}, line {x.line}: {x.snippet}\n\n"
                    f"Acceptance: {FIX_SHAPE.get(x.rule, 'the rule no longer fires')}. MOMUS re-runs this rule on "
                    f"{x.path} at the fix branch; an intentional exception is written in the code as "
                    "`# vx-ok: <reason>` on the line or the line above."),
            request_summary=json.dumps(focus, sort_keys=True),
            response_summary=f"{x.path}:{x.line}: {x.snippet}",
            reproducer=f"python3 scripts/vulnetix_class_scan.py {x.path}",
            reference_artifacts=(x.path,),
        )


def focus_from_finding(stored: dict[str, Any]) -> dict[str, str] | None:
    """The (rule, path, function) a stored code finding is about — kept in its evidence request snippet."""
    ev = stored.get("evidence") or {}
    return _focus_of(str(ev.get("request_snippet") or ""))


__all__ = ["CodeTarget", "VulnetixClassProbe", "RULES", "focus_from_finding"]
