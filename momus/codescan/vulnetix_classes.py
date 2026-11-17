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
                            Fixed shape: connect to the checked, pinned address. Also flagged (2026-11-16, three
                            MOMUS-loop fixes did this): after the check, a SECOND lookup (`getaddrinfo`, or a helper
                            returning its answer) whose address no check examines, and a request to that address --
                            the same rebinding gap with an extra step. The checked address is the connected one.
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


def _accepted(lines: list[str], lineno: int, honored: set[str] | None = None) -> bool:
    """A `# vx-ok: <reason>` on the line or the line above. With `honored` (a fix branch being gated), only marks
    that already exist on the base branch count: a fix may not accept its own finding (2026-11-16, MOMUS's first
    live loop: the fixer added a vx-ok line and the gate called it fixed)."""
    for n in (lineno - 1, lineno - 2):
        if 0 <= n < len(lines) and OK_MARK.search(lines[n]):
            if honored is None or lines[n].strip() in honored:
                return True
    return False


def ok_marks(source: str) -> set[str]:
    """The acceptance marks of a file, as stripped lines — what a fix branch is compared against."""
    return {line.strip() for line in source.splitlines() if OK_MARK.search(line)}


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


RESOLVERS = {"getaddrinfo", "gethostbyname", "gethostbyname_ex"}
_NOT_A_CHECK = {"len", "bool", "list", "tuple", "set", "sorted", "str", "int", "dict", "iter", "next", "enumerate",
                "reversed", "fromkeys", "split", "strip", "lower", "encode", "decode", "format", "join"}


def _ids(node: ast.AST | None) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} if node is not None else set()


def _bindings(fn: ast.AST) -> list[tuple[set[str], ast.AST]]:
    """(names bound, the expression they come from) for assignments, loops, comprehensions and walrus."""
    out: list[tuple[set[str], ast.AST]] = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            out.append((set().union(*(_ids(t) for t in n.targets)), n.value))
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            out.append((_ids(n.target), n.value))
        elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
            out.append((_ids(n.target), n.iter))
        elif isinstance(n, ast.NamedExpr):
            out.append(({n.target.id}, n.value))
        elif isinstance(n, ast.withitem) and n.optional_vars is not None:
            out.append((_ids(n.optional_vars), n.context_expr))
    return out


def _examines(node: ast.AST, names: set[str]) -> bool:
    """A call (not len/str/...) or an `.is_*` test that looks at one of `names`: an emptiness test does not count."""
    for c in ast.walk(node):
        if isinstance(c, ast.Call) and _callee_name(c) not in _NOT_A_CHECK and _callee_name(c) not in RESOLVERS \
                and any(_ids(a) & names for a in [*c.args, *(k.value for k in c.keywords)]):
            return True
        if isinstance(c, ast.Attribute) and c.attr.startswith("is_") and _ids(c.value) & names:
            return True
        if isinstance(c, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in c.ops) \
                and _ids(c.left) & names:
            return True
    return False


def _leaves(body: list[ast.stmt]) -> bool:
    return any(isinstance(b, (ast.Return, ast.Raise, ast.Continue, ast.Break)) for b in body)


def _resolution_flow(fn: ast.AST, resolvers: set[str], stopping: set[int]):
    """Addresses from a DNS lookup in `fn`: ({name: lookup call}, {lookup calls whose answer a check examined})."""
    binds = _bindings(fn)
    origin: dict[str, ast.Call] = {}
    for names, value in binds:
        src = next((c for c in ast.walk(value) if isinstance(c, ast.Call) and _callee_name(c) in resolvers), None)
        if src is not None:
            for nm in names:
                origin.setdefault(nm, src)
    changed = True
    while changed:
        changed = False
        for names, value in binds:
            src = next((origin[u] for u in sorted(_ids(value)) if u in origin), None)
            for nm in names:
                if src is not None and nm not in origin:
                    origin[nm], changed = src, True
    examined: set[int] = set()

    def mark(node: ast.AST) -> None:
        for nm, src in origin.items():
            if _examines(node, {nm}):
                examined.add(id(src))

    for n in ast.walk(fn):
        if isinstance(n, ast.If) and _leaves(n.body):
            mark(n.test)
        elif isinstance(n, ast.comprehension):
            for cond in n.ifs:
                mark(cond)
        elif isinstance(n, ast.Call) and id(n) in stopping and VALIDATOR.search(_callee_name(n)) \
                and _callee_name(n) not in resolvers:
            mark(n)
    return origin, examined


def _stopping_calls(fn: ast.AST) -> set[int]:
    """Calls that can stop the request: a bare call (raises), inside `try`, in a leaving `if` test, or assigned to
    a name a leaving `if` tests. A check that only prints a warning is not a guard."""
    stopping: set[int] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Expr) and isinstance(node.value, (ast.Call, ast.Await)):
            stopping.add(id(node.value.value if isinstance(node.value, ast.Await) else node.value))
        elif isinstance(node, ast.If) and _leaves(node.body):
            stopping.update(id(c) for c in ast.walk(node.test) if isinstance(c, ast.Call))
        elif isinstance(node, ast.Try):
            stopping.update(id(c) for st in node.body for c in ast.walk(st) if isinstance(c, ast.Call))
    leaving_tests = {n for i in ast.walk(fn) if isinstance(i, ast.If) and _leaves(i.body) for n in _names_in(i.test)}
    for node in ast.walk(fn):  # refusal = await check(url); if refusal: return
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in leaving_tests for t in node.targets):
            stopping.update(id(c) for c in ast.walk(node.value) if isinstance(c, ast.Call))
    return stopping


def unchecked_resolvers(tree: ast.AST) -> set[str]:
    """Functions in this file that return an address from a lookup no check examined (`_resolve_pinned_host`)."""
    fns = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    found: set[str] = set()
    for _ in range(3):  # helpers that call helpers
        resolvers = RESOLVERS | found
        for fn in fns:
            if fn.name in found:
                continue
            origin, examined = _resolution_flow(fn, resolvers, _stopping_calls(fn))
            for r in (n for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value is not None):
                if any(nm in origin and id(origin[nm]) not in examined for nm in _ids(r.value)):
                    found.add(fn.name)
                    break
    return found


class _Scanner(ast.NodeVisitor):
    def __init__(self, path: str, source: str, honored: set[str] | None = None,
                 resolvers: set[str] | None = None) -> None:
        self.resolvers = RESOLVERS | (resolvers or set())
        self.path, self.lines, self.findings = path, source.splitlines(), []
        self.honored = honored
        self.func: list[str] = []
        self.trust: list[bool] = []  # inside an `if` whose test checks the peer
        self.local: list[bool] = []  # inside an `if` whose test limits it to this host
        self.trusted_after: list[int] = []  # a guard `if not peer_is_proxy(...): return` ended on this line
        self.guarded_vars: set[str] = set()  # names tested together with a trust check in this function
        self.assigning: list[str] = []

    def add(self, rule: str, node: ast.AST, message: str) -> None:
        line = getattr(node, "lineno", 1)
        if _accepted(self.lines, line, self.honored):
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
        stopping = _stopping_calls(fn)
        calls = sorted((n for n in ast.walk(fn) if isinstance(n, ast.Call)), key=lambda n: (n.lineno, n.col_offset))
        origin, examined = _resolution_flow(fn, self.resolvers, stopping)
        parents: dict[str, set[str]] = {}
        for names, value in _bindings(fn):
            for nm in names:
                parents.setdefault(nm, set()).update(_ids(value))

        def lineage(src: ast.Call) -> set[str]:
            """Names the lookup's input comes from (host <- parsed <- url)."""
            seen, todo = set(), set().union(*(_ids(a) for a in src.args[:1])) if src.args else set()
            while todo:
                nm = todo.pop()
                if nm not in seen:
                    seen.add(nm)
                    todo |= parents.get(nm, set())
            return seen | {derived.get(n, n) for n in seen}

        for call in calls:
            name = _callee_name(call)
            if VALIDATOR.search(name) and name not in HTTP_METHODS and name not in self.resolvers - RESOLVERS \
                    and id(call) in stopping:
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
                    second = next((u for u in sorted(_ids(arg)) if u in origin and id(origin[u]) not in examined
                                   and lineage(origin[u]) & set(checked)), None)
                    if second:
                        src = origin[second]
                        self.add("VX-918-CHECK-THEN-CONNECT", call,
                                 f"{second!r} comes from a second lookup ({_callee_name(src)}, line {src.lineno}) that "
                                 "no check examines, so the request goes to an unchecked DNS answer: the same "
                                 "rebinding gap (check every address that lookup returns, connect to one that "
                                 "passed, keep the name in Host and TLS SNI)")
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



# --- Rules added 2026-11-16 from outside code (published pip advisories, artifacts/momus-outside-cves-2026-11-16) ----
#
#   VX-295-TLS-OFF            TLS certificate checking switched off in code: verify=False, ssl=False, CERT_NONE,
#                             check_hostname=False, _create_unverified_context (JS/TS: rejectUnauthorized: false,
#                             NODE_TLS_REJECT_UNAUTHORIZED=0). A flag from config (verify=self.verify) is not flagged.
#   VX-918-FETCH-UNCHECKED    an entry point (route handler, agent tool, MCP tool) passes a URL-like parameter
#                             straight to an HTTP client, and nothing in the function checks the address.
#   VX-918-REDIRECT-AFTER-CHECK  the address is checked, then fetched with redirects followed (requests' default,
#                             httpx follow_redirects=True, urlopen): the checked host answers 302 to an inner one.
#   VX-306-ROUTE-NO-AUTH      a module creates its web app (FastAPI/Flask/Starlette/Quart/Sanic) and serves
#                             state-changing routes on it (POST/PUT/PATCH/DELETE) with no authentication vocabulary
#                             at all: no key, token, user, session, permission or login check anywhere. Routers
#                             mounted elsewhere are not judged: the app that mounts them may guard them.

URL_PARAM = re.compile(r"(?i)^(url|uri|link|href|endpoint|target|address|src|source_url|.*_(url|uri|endpoint|address|"
                       r"link)|webhook\w*|callback\w*|redirect\w*)$")
ENTRY_DECORATOR = re.compile(r"(?i)(^|\.)(get|post|put|patch|delete|route|api_route|websocket|tool|call_tool|"
                             r"function_tool|resource|prompt|handler|endpoint)$")
TOOL_CLASS = re.compile(r"(Tool|Loader|Fetcher|Scraper|Crawler|Reader|Retriever|Browser|Spider|Downloader)s?$")
TOOL_METHOD = {"_run", "_arun", "run", "arun", "invoke", "ainvoke", "__call__", "execute", "load", "lazy_load",
               "fetch", "scrape", "crawl", "download"}
FETCH_CALLS = {"get", "post", "put", "patch", "request", "stream", "head", "urlopen", "urlretrieve", "fetch",
               "ws_connect", "goto", "download"}
URL_CHECK = re.compile(r"(?i)(ssrf|safe_?url|url_?safe|is_safe|validate_?(url|host|target|address)|check_?(url|host|target)|"
                       r"allowed_?(host|url)|is_public|public_(ip|addr|host)|is_private|private_(ip|addr)|guard|blocked_?(host|ip))")
SAFE_CLIENT = re.compile(r"(?i)(safe|guard|ssrf|pinned|allowlist|whitelist)")
AUTH_WORDS = re.compile(r"(?i)(auth|token|api_?key|apikey|secret|password|passwd|credential|current_user|get_user|"
                        r"login|session|permission|scope|bearer|jwt|oauth|signature|hmac|verify_|is_admin|"
                        r"require_|depends\(|security|principal|acl|role)")
WRITE_DECORATOR = re.compile(r"(?i)(^|\.)(post|put|patch|delete)$")
ROUTE_CALL = re.compile(r"(?i)(^|\.)(route|api_route|add_url_rule|add_api_route)$")


def _dotted(node: ast.AST) -> str:
    """`requests.get`, `self.session.get`, `app.post` — the whole attribute chain (_callee_name keeps the last part)."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) + "()")
    return ".".join(reversed(parts))


def _decorator_name(d: ast.AST) -> str:
    return _dotted(d.func) if isinstance(d, ast.Call) else _dotted(d)


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _is_false(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


class _Outside(ast.NodeVisitor):
    """The 2026-11-16 rules. Separate from _Scanner: they look at whole functions and modules, not at nested
    trust scopes."""

    def __init__(self, path: str, source: str, honored: set[str] | None) -> None:
        self.path, self.lines, self.honored, self.findings = path, source.splitlines(), honored, []
        self.func: list[str] = []
        self.cls: list[str] = []
        self.write_routes: list[ast.AST] = []
        self.local_if: list[bool] = []
        self.pinning: list[bool] = []  # function compares the peer certificate itself (getpeercert / fingerprint)
        self.apps: set[str] = set()  # FastAPI()/Flask()/Starlette() objects created in this module

    def add(self, rule: str, node: ast.AST, message: str) -> None:
        line = getattr(node, "lineno", 1)
        if _accepted(self.lines, line, self.honored):
            return
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.findings.append(Finding(rule, self.path, line, ".".join(self.func) or "<module>", message, snippet[:200]))

    # TLS ------------------------------------------------------------------------------------------------------------
    def _pins_cert(self) -> bool:
        """Certificate checks relaxed on purpose: the function compares the certificate itself, or the code sits
        under an `if` that limits it to a loopback peer (a local relay)."""
        return (self.pinning[-1] if self.pinning else False) or any(self.local_if)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        self.local_if.append(any(LOCAL_ONLY.search(n) for n in _names_in(node.test)))
        for st in node.body:
            self.visit(st)
        self.local_if.pop()
        for st in node.orelse:
            self.visit(st)

    def visit_Call(self, node: ast.Call) -> None:
        if self._pins_cert():
            self.generic_visit(node)
            return
        name = _callee_name(node.func)
        short = name.rsplit(".", 1)[-1]
        if _is_false(_kw(node, "verify")) or _is_false(_kw(node, "verify_ssl")) or (
                _is_false(_kw(node, "ssl")) and short in FETCH_CALLS | {"TCPConnector", "ClientSession"}):
            self.add("VX-295-TLS-OFF", node, "TLS certificate checking is switched off for this request: anyone on the "
                     "path can answer for the host (leave verification on; pass a CA bundle if the host has its own)")
        elif short in ("_create_unverified_context", "_create_stdlib_context"):
            self.add("VX-295-TLS-OFF", node, "an unverified TLS context: certificates are not checked")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "CERT_NONE" and isinstance(node.ctx, ast.Load) and not self._pins_cert():
            self.add("VX-295-TLS-OFF", node, "ssl.CERT_NONE: certificates are not checked")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            if isinstance(t, ast.Attribute) and t.attr in ("check_hostname", "verify") and _is_false(node.value) \
                    and not self._pins_cert():
                self.add("VX-295-TLS-OFF", node, f"{t.attr} = False: the peer's certificate or name is not checked")
        self.generic_visit(node)

    # entry points ---------------------------------------------------------------------------------------------------
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.cls.append(node.name)
        self.generic_visit(node)
        self.cls.pop()

    def _entry(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if any(ENTRY_DECORATOR.search(_decorator_name(d)) for d in node.decorator_list):
            return True
        return bool(self.cls) and bool(TOOL_CLASS.search(self.cls[-1])) and node.name in TOOL_METHOD

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.func.append(node.name)
        self.pinning.append(bool(re.search(r"(?i)getpeercert|fingerprint|pinned_?(cert|sha|spki)|cert_?pin",
                                           ast.unparse(node))))
        decos = [_decorator_name(d) for d in node.decorator_list]
        methods = set()
        for d in node.decorator_list:
            if isinstance(d, ast.Call) and ROUTE_CALL.search(_decorator_name(d)):
                m = _kw(d, "methods")
                if isinstance(m, (ast.List, ast.Tuple, ast.Set)):
                    methods |= {e.value.upper() for e in m.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
        on_app = [x for x in decos if x.split(".")[0] in self.apps]
        if any(WRITE_DECORATOR.search(x) for x in on_app) or (methods & {"POST", "PUT", "PATCH", "DELETE"} and on_app):
            self.write_routes.append(node)
        if self._entry(node):
            self._fetch_unchecked(node)
        self._redirect_after_check(node)
        self.generic_visit(node)
        self.pinning.pop()
        self.func.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def _url_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        return {a.arg for a in args if URL_PARAM.match(a.arg)}

    def _tainted(self, node: ast.FunctionDef | ast.AsyncFunctionDef, seeds: set[str]) -> set[str]:
        tainted = set(seeds)
        for _ in range(3):  # names assigned from a tainted expression (url2 = url.strip(); full = f"{base}{path}")
            for n in ast.walk(node):
                if isinstance(n, ast.Assign) and _names_in(n.value) & tainted:
                    tainted |= {t.id for t in n.targets if isinstance(t, ast.Name)}
                if isinstance(n, (ast.For, ast.comprehension)) and _names_in(n.iter) & tainted \
                        and isinstance(n.target, ast.Name):
                    tainted.add(n.target.id)
        return tainted

    @staticmethod
    def _fetches(node: ast.AST):
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                name = _dotted(n.func)
                short = name.rsplit(".", 1)[-1]
                obj = name.rsplit(".", 1)[0] if "." in name else ""
                if short in FETCH_CALLS and (short in HTTP_FUNCS or HTTP_OBJECT.search(obj.rsplit(".", 1)[-1] or "")
                                             or obj.split(".")[0] in ("requests", "httpx", "urllib", "aiohttp")):
                    target = n.args[0] if n.args else (_kw(n, "url") or _kw(n, "uri"))
                    yield n, name, obj, target

    @staticmethod
    def _checks(node: ast.AST) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and VALIDATOR.search(_callee_name(n.func).rsplit(".", 1)[-1]):
                return True
        return False

    def _fetch_unchecked(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        params = self._url_params(node)
        if not params or self._checks(node):
            return
        tainted = self._tainted(node, params)
        for call, name, obj, target in self._fetches(node):
            if target is not None and _names_in(target) & tainted and not SAFE_CLIENT.search(name):
                self.add("VX-918-FETCH-UNCHECKED", call,
                         f"{node.name}() fetches the caller's URL ({', '.join(sorted(_names_in(target) & tainted))}) "
                         "with no check of where it points: internal hosts and cloud metadata are reachable "
                         "(resolve, refuse private/loopback/link-local addresses, connect to the checked one)")
                return

    def _redirect_after_check(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        checked = set()
        for n in ast.walk(node):
            callee = _callee_name(n.func).rsplit(".", 1)[-1] if isinstance(n, ast.Call) else ""
            if callee and "b64" not in callee and URL_CHECK.search(callee):
                for a in [*n.args, *(k.value for k in n.keywords)]:
                    checked |= _names_in(a)
        if not checked:
            return
        checked = self._tainted(node, checked)
        for call, name, obj, target in self._fetches(node):
            if SAFE_CLIENT.search(name) or target is None or not (_names_in(target) & checked):
                continue
            short = name.rsplit(".", 1)[-1]
            root = obj.split(".")[0]
            follows = False
            if short in HTTP_FUNCS:
                follows = True
            elif root == "requests" or (obj and re.search(r"(?i)session", obj.rsplit(".", 1)[-1])):
                follows = short != "head" and not _is_false(_kw(call, "allow_redirects"))
            elif _is_true(_kw(call, "follow_redirects")) or _is_true(_kw(call, "allow_redirects")):
                follows = True
            if follows:
                self.add("VX-918-REDIRECT-AFTER-CHECK", call,
                         "the address is checked, then fetched with redirects followed: the checked host can answer "
                         "302 to an internal one (allow_redirects=False / follow_redirects=False and check each hop)")
                return

    def finish(self, tree: ast.AST) -> None:
        if not self.write_routes:
            return
        if AUTH_WORDS.search("\n".join(self.lines)):
            return
        self.func = [self.write_routes[0].name]
        self.add("VX-306-ROUTE-NO-AUTH", self.write_routes[0],
                 f"{len(self.write_routes)} state-changing route(s) in a module with no authentication at all "
                 "(no key, token, user, session or permission check): anyone who reaches the port can call them")
        self.func = []


JS_TLS_OFF = re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\]?\s*=\s*['\"]?0|"
                        r"strictSSL\s*:\s*false|checkServerIdentity\s*:\s*\(\)\s*=>\s*(undefined|null|\{\s*\})")
JS_REQ_URL = re.compile(r"\b(fetch|axios(?:\.(?:get|post|request))?|got(?:\.(?:get|post))?|request|https?\.(?:get|request)|"
                        r"undici\.request|page\.goto)\s*\(\s*(?:new URL\(\s*)?req(?:uest)?\.(?:query|body|params)\b")
JS_VALIDATOR = re.compile(r"(?i)(isPrivate|isPublic|ssrf|safe(Url|Fetch|Host)|allowed_?host|validate_?(url|host|target)|"
                          r"dns\.lookup|lookup\(|ipaddr|isLoopback|blockList|BlockList)")
JS_WRITE_ROUTE = re.compile(r"\b(app|router|server|fastify)\.(post|put|patch|delete)\s*\(")
JS_AUTH = re.compile(r"(?i)(auth|token|api_?key|apikey|secret|password|session|passport|jwt|bearer|permission|"
                     r"credential|signature|hmac|login|currentUser|req\.user)")
JS_FILE = re.compile(r"\.(m?js|cjs|ts|mts|cts)$")


def scan_js(path: str, source: str, honored: set[str] | None = None) -> list[Finding]:
    """Line-level JS/TS rules (no parser): TLS off, a request URL taken from req.query/body/params with no check
    anywhere in the file, and write routes in a file with no authentication vocabulary."""
    out: list[Finding] = []
    lines = source.splitlines()

    def add(rule: str, i: int, msg: str) -> None:
        if not _accepted(lines, i, honored) and not any(
                lines[n].lstrip().startswith(("//", "*", "/*")) for n in (i - 1,) if 0 <= n < len(lines)):
            out.append(Finding(rule, path, i, "<file>", msg, lines[i - 1].strip()[:200]))

    has_check = bool(JS_VALIDATOR.search(source))
    for i, line in enumerate(lines, 1):
        if JS_TLS_OFF.search(line):
            add("VX-295-TLS-OFF", i, "TLS certificate checking is switched off: anyone on the path can answer for "
                "the host")
        if not has_check and JS_REQ_URL.search(line):
            add("VX-918-FETCH-UNCHECKED", i, "a request goes to an address taken from the caller's request with no "
                "check of where it points")
    writes = [i for i, line in enumerate(lines, 1) if JS_WRITE_ROUTE.search(line)]
    if writes and not JS_AUTH.search(source):
        add("VX-306-ROUTE-NO-AUTH", writes[0], f"{len(writes)} state-changing route(s) in a file with no "
            "authentication at all: anyone who reaches the port can call them")
    return out


def scan_python(path: str, source: str, honored: set[str] | None = None) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError):
        return []
    s = _Scanner(path, source, honored, unchecked_resolvers(tree))
    s.visit(tree)
    o = _Outside(path, source, honored)
    o.apps = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
              and _callee_name(n.value.func).rsplit(".", 1)[-1] in ("FastAPI", "Flask", "Starlette", "Quart", "Sanic")
              for t in n.targets if isinstance(t, ast.Name)}
    o.visit(tree)
    o.finish(tree)
    return s.findings + o.findings


def scan_text(path: str, source: str, honored: set[str] | None = None) -> list[Finding]:
    out = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        if SSH_NO_HOSTKEY.search(line) and not _accepted(lines, i, honored):
            out.append(Finding("VX-SSH-NO-HOSTKEY", path, i, "<file>",
                               "ssh without host-key checking: the first answer on that address is trusted "
                               "(use StrictHostKeyChecking=accept-new with a pinned known_hosts)", line.strip()[:200]))
    return out


def scan_file(path: str, source: str, honored: set[str] | None = None) -> list[Finding]:
    """Findings in one file. `honored`: when set, only these acceptance marks count (see _accepted)."""
    if EXCLUDE.search(path):
        return []
    found = scan_python(path, source, honored) if path.endswith(".py") else []
    if SSH_FILE.search(path) and not path.endswith(".py"):
        found += scan_text(path, source, honored)
    if JS_FILE.search(path) and not path.endswith(".d.ts") and not re.search(r"\.min\.js$", path):
        found += scan_js(path, source, honored)
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
