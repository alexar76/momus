#!/usr/bin/env python3
"""Code scan for the bug classes Vulnetix found in this monorepo (October 2026), so the next one is caught at push.

MOMUS probes the live economy contract from outside and never reads code; none of these classes was in reach of
its probes. Each rule below is written from the code as it was BEFORE the fix commits (5ad17c13a, 85db7deea,
e35551666), and stays quiet on the fixed shape:

  VX-306-OPEN-WITHOUT-KEY   an auth check that lets every caller in when no key is configured
                            (platon `_write_authorized`: "return True  # public demo"; metis `verify_api_key` outside
                            production). Fixed shape: no key -> local callers only (`local_caller(request)`).
  VX-918-CHECK-THEN-CONNECT the URL's host is resolved/checked, then the request goes to the same URL by NAME, so DNS
                            can answer differently the second time (atlas webhooks, aimarket-mcp web_fetch).
                            Fixed shape: connect to the checked, pinned address.
  VX-FWD-HEADER-TRUST       the caller's identity taken from X-Real-IP / X-Forwarded-For without first checking that
                            the socket peer is a trusted proxy (oracle_core `client_key`, platon, logos, attested ...).
                            Fixed shape: read the header only inside `if peer_is_local_proxy(peer):`-like checks.
  VX-918-UNPINNED-RETURN    a "pin the target" helper that hands back the URL it was given (aimarket-mcp `pin_target`,
                            alien-monitor `_pin_http_target`: HTTPS was never pinned), so the caller connects by name.
  VX-SSH-NO-HOSTKEY         `StrictHostKeyChecking=no` (SKOPOS remediation git push). Fixed: accept-new + known_hosts;
                            kept only for a remote on this host, inside `if ssh_remote_is_local(...)`.

A finding is accepted in code with a comment on the flagged line or the line above it:
    # vx-ok: <why this is safe here>
A reason is required; an empty `vx-ok:` does not count.

Usage:
  vulnetix_class_scan.py [PATH ...]                 scan files/dirs of the working tree (default: repo root)
  vulnetix_class_scan.py --ref REF                  scan the committed tree at REF
  vulnetix_class_scan.py --ref REF --base BASE      report only findings new at REF compared with BASE
  --json                                            machine-readable output
Exit: 0 clean, 1 findings. Stdlib only.
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path

FWD_HEADERS = {"x-real-ip", "x-forwarded-for", "forwarded", "cf-connecting-ip", "true-client-ip", "x-client-ip",
               "x-cluster-client-ip", "fastly-client-ip"}
TRUST_CHECK = re.compile(r"(?i)(proxy|proxies|trusted|loopback|is_private|private_peer|local_?caller|peer_is|from_lb)")
AUTH_FUNC = re.compile(r"(?i)(verify|check|require|authori[sz]ed|allowed|authenticate|permit|is_operator|gate)")
SECRETISH = re.compile(r"(?i)(token|key|secret|expected|password|passwd|credential|auth)")
VALIDATOR = re.compile(r"(?i)(getaddrinfo|gethostbyname|resolve|public|private|ssrf|safe|allowed_?host|guard|"
                       r"validate_?(url|host|target)|check_?(url|host|target))")
LOCAL_ONLY = re.compile(r"(?i)(local|loopback)")
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "request", "stream", "head", "send", "urlopen", "urlretrieve",
                "ws_connect", "fetch"}
HTTP_OBJECT = re.compile(r"(?i)(client|session|http|requests|urllib|aiohttp|conn|transport|fetcher|^c$|^s$)")
HTTP_FUNCS = {"urlopen", "urlretrieve"}
SSH_NO_HOSTKEY = re.compile(r"StrictHostKeyChecking\s*[= ]\s*['\"]?no\b", re.I)
SSH_FILE = re.compile(r"(\.(py|sh|bash|ya?ml|toml|js|mjs|ts|cfg|conf|ini|env)$|(^|/)Dockerfile[^/]*$|(^|/)ssh_config$)")
EXCLUDE = re.compile(r"(^|/)(artifacts|docs|node_modules|\.venv|venv|vendor|site-packages|dist|build|__pycache__|"
                     r"tests?|fixtures|testdata)(/|$)|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$")
OK_MARK = re.compile(r"vx-ok:\s*\S")


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    function: str
    message: str
    snippet: str

    @property
    def key(self) -> str:
        """Stable across unrelated edits: no line number."""
        return f"{self.rule}|{self.path}|{self.function}|{' '.join(self.snippet.split())}"


def _accepted(lines: list[str], lineno: int) -> bool:
    for n in (lineno - 1, lineno - 2):
        if 0 <= n < len(lines) and OK_MARK.search(lines[n]):
            return True
    return False


def _callee_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}


class _Scanner(ast.NodeVisitor):
    def __init__(self, path: str, source: str) -> None:
        self.path, self.lines, self.findings = path, source.splitlines(), []
        self.func: list[str] = []
        self.trust: list[bool] = []  # inside an `if` whose test checks the peer
        self.local: list[bool] = []  # inside an `if` whose test limits it to this host
        self.trusted_after: list[int] = []  # a guard `if not peer_is_proxy(...): return` ended on this line
        self.guarded_vars: set[str] = set()  # names tested together with a trust check in this function
        self.assigning: list[str] = []

    def add(self, rule: str, node: ast.AST, message: str) -> None:
        line = getattr(node, "lineno", 1)
        if _accepted(self.lines, line):
            return
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.findings.append(Finding(rule, self.path, line, ".".join(self.func) or "<module>", message, snippet[:200]))

    # --- scopes -------------------------------------------------------------------------------------------------
    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.func.append(node.name)
        self._check_open_without_key(node)
        self._check_then_connect(node)
        self._check_unpinned_return(node)
        guard = 10 ** 9
        for stmt in node.body:  # `if not trusted(peer): return peer` -> the rest of the function is behind the check
            if isinstance(stmt, ast.If) and not stmt.orelse and stmt.body \
                    and isinstance(stmt.body[-1], (ast.Return, ast.Raise)) \
                    and any((isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not)
                             and any(TRUST_CHECK.search(m) for m in _names_in(n.operand)))
                            or (isinstance(n, ast.Compare) and any(isinstance(o, ast.NotIn) for o in n.ops)
                                and any(TRUST_CHECK.search(m) for c in n.comparators for m in _names_in(c)))
                            for n in ast.walk(stmt.test)):
                guard = stmt.end_lineno or stmt.lineno
                break
        self.guarded_vars = {n for test in (i.test for i in ast.walk(node) if isinstance(i, (ast.If, ast.IfExp)))
                             if any(TRUST_CHECK.search(m) for m in _names_in(test))
                             for n in _names_in(test)}
        saved, self.trust = self.trust, []
        self.trusted_after.append(guard)
        self.generic_visit(node)
        self.trusted_after.pop()
        self.trust = saved
        self.func.pop()

    def _trusted(self, node: ast.AST) -> bool:
        return any(self.trust) or bool(TRUST_CHECK.search(".".join(self.func))) or (
            bool(self.trusted_after) and getattr(node, "lineno", 0) > self.trusted_after[-1]) or (
            bool(self.assigning) and self.assigning[-1] in self.guarded_vars)

    def visit_Assign(self, node: ast.Assign) -> None:
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        self.assigning.append(names[0] if len(names) == 1 else "")
        self.visit(node.value)
        self.assigning.pop()
        for t in node.targets:
            self.visit(t)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        self.trust.append(any(TRUST_CHECK.search(n) for n in _names_in(node.test)))
        self.visit(node.body)
        self.trust.pop()
        self.visit(node.orelse)

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return  # a docstring or bare string: prose about a setting is not the setting
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and SSH_NO_HOSTKEY.search(node.value) and not any(self.local):
            self.add("VX-SSH-NO-HOSTKEY", node, "ssh without host-key checking: the first answer on that address is "
                     "trusted (use StrictHostKeyChecking=accept-new with a pinned known_hosts)")

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.func.append(node.name)
        self.generic_visit(node)
        self.func.pop()

    def visit_If(self, node: ast.If) -> None:
        names = _names_in(node.test)
        checks_peer = any(TRUST_CHECK.search(n) for n in names)
        local_only = any(LOCAL_ONLY.search(n) for n in names)
        self.visit(node.test)
        self.trust.append(checks_peer)
        self.local.append(local_only)
        for stmt in node.body:
            self.visit(stmt)
        self.trust.pop()
        self.local.pop()
        self.trust.append(False)
        self.local.append(False)
        for stmt in node.orelse:
            self.visit(stmt)
        self.trust.pop()
        self.local.pop()

    # --- VX-FWD-HEADER-TRUST -------------------------------------------------------------------------------------
    def _fwd_header(self, node: ast.AST) -> str | None:
        target, key = None, None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getlist") \
                and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            target, key = node.func.value, node.args[0].value
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            target, key = node.value, node.slice.value
        if target is None or key is None or key.lower() not in FWD_HEADERS:
            return None
        return key if "header" in _callee_name(target).lower() or (
            isinstance(target, ast.Attribute) and "header" in target.attr.lower()) or (
            isinstance(target, ast.Name) and "header" in target.id.lower()) else None

    def visit_Call(self, node: ast.Call) -> None:
        if any(TRUST_CHECK.search(n) for a in [*node.args, *(k.value for k in node.keywords)] for n in _names_in(a)
               if not self._fwd_header(a)) or TRUST_CHECK.search(_callee_name(node)):
            self.trust.append(True)  # e.g. _announced_relay(peer, xff, _TRUSTED_PROXIES): the callee does the check
            self.generic_visit(node)
            self.trust.pop()
            return
        header = self._fwd_header(node)
        if header and not self._trusted(node):
            self.add("VX-FWD-HEADER-TRUST", node,
                     f"client identity read from {header!r} without first checking that the socket peer is a trusted "
                     "proxy; any caller that reaches the port directly can set it")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        header = self._fwd_header(node)
        if header and isinstance(node.ctx, ast.Load) and not self._trusted(node):
            self.add("VX-FWD-HEADER-TRUST", node, f"client identity read from {header!r} without a trusted-proxy check")
        self.generic_visit(node)

    # --- VX-306-OPEN-WITHOUT-KEY ---------------------------------------------------------------------------------
    def _check_open_without_key(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if not AUTH_FUNC.search(fn.name):
            return
        for node in ast.walk(fn):
            if not isinstance(node, ast.If) or not node.body or not isinstance(node.body[-1], ast.Return):
                continue
            ret = node.body[-1].value
            permissive = ret is None or (isinstance(ret, ast.Constant) and ret.value in (True, None))
            if not permissive:
                continue
            body_names = set().union(*(_names_in(b) for b in node.body))
            if any(TRUST_CHECK.search(n) for n in body_names) or any(isinstance(n, ast.Raise) for b in node.body
                                                                       for n in ast.walk(b)):
                continue  # no key -> local callers only, or refuses on some path: the fixed shape
            negated = [n for n in ast.walk(node.test) if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not)
                       and isinstance(n.operand, (ast.Name, ast.Attribute))]
            if any(SECRETISH.search(" ".join(_names_in(n.operand))) for n in negated):
                self.add("VX-306-OPEN-WITHOUT-KEY", node,
                         f"{fn.name}() lets every caller in when no key is configured; outside production that is "
                         "anyone who can reach the port (limit it to local callers or refuse)")

    # --- VX-918-CHECK-THEN-CONNECT -------------------------------------------------------------------------------
    def _check_then_connect(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        derived: dict[str, str] = {}  # host var -> url var (host = urlsplit(url).hostname)
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                v = node.value
                while isinstance(v, (ast.Attribute, ast.BoolOp)):
                    v = v.value if isinstance(v, ast.Attribute) else v.values[0]
                if isinstance(v, ast.Call) and _callee_name(v) in ("urlsplit", "urlparse") and v.args \
                        and isinstance(v.args[0], ast.Name):
                    derived[node.targets[0].id] = v.args[0].id
        checked: dict[str, int] = {}
        # A check counts when it can stop the request: a bare call (raises), inside `try` whose handler
        # leaves, or in an `if` test whose body leaves. A check that only prints a warning is not a guard.
        stopping: set[int] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Expr) and isinstance(node.value, (ast.Call, ast.Await)):
                stopping.add(id(node.value.value if isinstance(node.value, ast.Await) else node.value))
            elif isinstance(node, ast.If) and any(isinstance(b, (ast.Return, ast.Raise, ast.Continue, ast.Break))
                                                 for b in node.body):
                stopping.update(id(c) for c in ast.walk(node.test) if isinstance(c, ast.Call))
            elif isinstance(node, ast.Try):
                stopping.update(id(c) for st in node.body for c in ast.walk(st) if isinstance(c, ast.Call))
        leaving_tests = {n for i in ast.walk(fn) if isinstance(i, ast.If) and any(
            isinstance(b, (ast.Return, ast.Raise, ast.Continue, ast.Break)) for b in i.body) for n in _names_in(i.test)}
        for node in ast.walk(fn):  # refusal = await check(url); if refusal: return
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in leaving_tests for t in node.targets):
                stopping.update(id(c) for c in ast.walk(node.value) if isinstance(c, ast.Call))
        calls = sorted((n for n in ast.walk(fn) if isinstance(n, ast.Call)), key=lambda n: (n.lineno, n.col_offset))
        for call in calls:
            name = _callee_name(call)
            if VALIDATOR.search(name) and name not in HTTP_METHODS and id(call) in stopping:
                for arg in call.args[:1]:
                    if isinstance(arg, ast.Name):
                        checked.setdefault(derived.get(arg.id, arg.id), call.lineno)
            elif name in HTTP_FUNCS or (name in HTTP_METHODS and isinstance(call.func, ast.Attribute)
                                         and HTTP_OBJECT.search(_callee_name(call.func.value) or "")):
                for arg in call.args[:2]:
                    used = [arg.id] if isinstance(arg, ast.Name) else [
                        v.value.id for v in getattr(arg, "values", []) if isinstance(v, ast.FormattedValue)
                        and isinstance(v.value, ast.Name)] if isinstance(arg, ast.JoinedStr) else []
                    hit = next((u for u in used if u in checked and checked[u] <= call.lineno), None)
                    if hit:
                        self.add("VX-918-CHECK-THEN-CONNECT", call,
                                 f"{hit!r} is checked (line {checked[hit]}) and then requested by name; a second DNS "
                                 "answer can point elsewhere (connect to the checked, pinned address instead)")
                        break

    def _check_unpinned_return(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if "pin" not in fn.name.lower():
            return
        params = {a.arg for a in fn.args.args + fn.args.kwonlyargs if re.search(r"(?i)url|target|uri", a.arg)}

        def lets_https_through(test: ast.AST) -> bool:
            for c in ast.walk(test):
                if isinstance(c, ast.Compare) and "scheme" in _names_in(c.left) | set().union(
                        *(_names_in(x) for x in c.comparators)):
                    for op, cmp in zip(c.ops, c.comparators):
                        consts = {x.value for x in ast.walk(cmp) if isinstance(x, ast.Constant)}
                        if (isinstance(op, (ast.NotEq, ast.NotIn)) and "http" in consts and "https" not in consts) \
                                or (isinstance(op, (ast.Eq, ast.In)) and "https" in consts):
                            return True
            return False

        risky = {id(r) for i in ast.walk(fn) if isinstance(i, ast.If) and lets_https_through(i.test)
                 for r in ast.walk(ast.Module(body=i.body, type_ignores=[])) if isinstance(r, ast.Return)}
        for node in ast.walk(fn):
            if not isinstance(node, ast.Return) or node.value is None or id(node) not in risky:
                continue
            v = node.value.elts[0] if isinstance(node.value, ast.Tuple) and node.value.elts else node.value
            if isinstance(v, ast.Name) and v.id in params:
                self.add("VX-918-UNPINNED-RETURN", node,
                         f"{fn.name}() returns {v.id!r} unpinned when the scheme is not plain http, so HTTPS "
                         "connects by name (pin the checked address and send the name as SNI, or refuse)")


def scan_python(path: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError):
        return []
    s = _Scanner(path, source)
    s.visit(tree)
    return s.findings


def scan_text(path: str, source: str) -> list[Finding]:
    out = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        if SSH_NO_HOSTKEY.search(line) and not _accepted(lines, i):
            out.append(Finding("VX-SSH-NO-HOSTKEY", path, i, "<file>",
                               "ssh without host-key checking: the first answer on that address is trusted "
                               "(use StrictHostKeyChecking=accept-new with a pinned known_hosts)", line.strip()[:200]))
    return out


def scan_file(path: str, source: str) -> list[Finding]:
    if EXCLUDE.search(path):
        return []
    found = scan_python(path, source) if path.endswith(".py") else []
    if SSH_FILE.search(path) and not path.endswith(".py"):
        found += scan_text(path, source)
    return found


def _iter_tree(root: Path, paths: list[str]):
    for p in paths or [str(root)]:
        p = Path(p)
        files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
        for f in files:
            rel = os.path.relpath(f, root)
            if EXCLUDE.search(rel) or not (rel.endswith(".py") or SSH_FILE.search(rel)):
                continue
            try:
                yield rel, f.read_text("utf-8", errors="replace")
            except OSError:
                continue


def _changed(root: Path, base: str, ref: str) -> list[str]:
    out = subprocess.run(["git", "-C", str(root), "diff", "--name-only", "--no-renames", base, ref], check=True,
                         capture_output=True, text=True).stdout.split()
    return [p for p in out if not EXCLUDE.search(p) and (p.endswith(".py") or SSH_FILE.search(p))]


def _iter_ref(root: Path, ref: str, only: list[str] | None = None):
    if only is not None and not only:
        return
    data = subprocess.run(["git", "-C", str(root), "archive", "--format=tar", ref, *(only or [])], check=False,
                          capture_output=True).stdout
    if not data:
        if only:  # a file deleted at this ref: archive refuses the whole list, so take what exists one by one
            for path in only:
                r = subprocess.run(["git", "-C", str(root), "show", f"{ref}:{path}"], capture_output=True)
                if r.returncode == 0:
                    yield path, r.stdout.decode("utf-8", errors="replace")
        return
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for m in tar:
            if not m.isfile() or EXCLUDE.search(m.name) or not (m.name.endswith(".py") or SSH_FILE.search(m.name)):
                continue
            fh = tar.extractfile(m)
            if fh is not None:
                yield m.name, fh.read().decode("utf-8", errors="replace")


def scan(items) -> list[Finding]:
    out: list[Finding] = []
    for path, source in items:
        out.extend(scan_file(path, source))
    return sorted(out, key=lambda f: (f.path, f.line, f.rule))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--ref")
    ap.add_argument("--base")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    root = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip()
                or ".")
    if a.base and not a.ref:
        ap.error("--base needs --ref")
    only = _changed(root, a.base, a.ref) if a.base else None  # judge the change: files it touched
    findings = scan(_iter_ref(root, a.ref, only) if a.ref else _iter_tree(root, a.paths))
    if a.base:
        old = {f.key for f in scan(_iter_ref(root, a.base, only))}
        findings = [f for f in findings if f.key not in old]
    if a.json:
        print(json.dumps([{**asdict(f), "key": f.key} for f in findings], indent=1))
    else:
        for f in findings:
            print(f"{f.path}:{f.line}: {f.rule} [{f.function}] {f.message}\n    {f.snippet}")
        label = "new " if a.base else ""
        print(f"vulnetix-class scan: {len(findings)} {label}finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
