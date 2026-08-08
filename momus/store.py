"""MOMUS's own vulnerability corpus — the personal database of holes it has found.

Findings used to live in an in-memory ring, which meant a restart erased MOMUS's memory of every
bug it had ever found. That undercuts the whole point of a self-learning auditor: it should get
sharper over time, and it should be able to say "I found this before" and "this one was refuted".
So findings are persisted properly, with a queryable schema.

Backends, in order of preference — the satellite must never NEED infrastructure to run:

    SQLite   (default)   stdlib, zero dependencies, real SQL + indexes, and an atomic UNIQUE
                         constraint on the dedup key. Perfect for a single MOMUS instance.
    Postgres (opt-in)    when MOMUS_DATABASE_URL / DATABASE_URL is set. Use this when several
                         MOMUS instances share one corpus, or when the monitor/BI needs to query
                         it alongside the rest of the ecosystem's data.

The schema is deliberately narrow: a finding, its verdicts, and the scan it came from. Payouts are
NOT here — money lives in the Treasury's own ledger, behind a different key, in a different
service. Keeping the corpus free of payout state is part of the separation: a compromised scanner
database cannot rewrite what was paid.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any, Iterator

from momus.findings import Finding

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id     TEXT PRIMARY KEY,
    dedup_key      TEXT NOT NULL,
    target         TEXT NOT NULL,
    target_kind    TEXT NOT NULL,
    probe          TEXT NOT NULL,
    category       TEXT NOT NULL,
    severity       TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    status         TEXT NOT NULL,
    title          TEXT NOT NULL,
    detail         TEXT NOT NULL,
    scanner_pubkey TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    first_seen_at  TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    seen_count     INTEGER NOT NULL DEFAULT 1,
    scan_id        TEXT,
    doc            TEXT NOT NULL          -- the full signed finding as JSON (source of truth)
);
-- One row per distinct BUG. A rediscovery bumps seen_count instead of inserting a duplicate,
-- which is what makes "have I seen this before?" answerable and keeps the corpus honest.
CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_dedup ON findings(dedup_key);
CREATE INDEX IF NOT EXISTS ix_findings_target   ON findings(target);
CREATE INDEX IF NOT EXISTS ix_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS ix_findings_status   ON findings(status);
CREATE INDEX IF NOT EXISTS ix_findings_seen     ON findings(last_seen_at);

CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    method          TEXT NOT NULL,
    score           REAL NOT NULL,
    verifier_id     TEXT NOT NULL,
    verifier_pubkey TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    doc             TEXT NOT NULL,
    UNIQUE(finding_id, verifier_pubkey, verdict)
);
CREATE INDEX IF NOT EXISTS ix_verdicts_finding ON verdicts(finding_id);

CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    targets     TEXT NOT NULL,
    provider    TEXT,
    counts      TEXT NOT NULL
);
"""

# Postgres needs the same shape with its own type names / upsert syntax.
_PG_SCHEMA = _SQLITE_SCHEMA.replace(
    "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY"
).replace("REAL", "DOUBLE PRECISION")


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def database_url() -> str:
    """Postgres DSN if the operator provided one, else empty (→ SQLite)."""
    return (os.environ.get("MOMUS_DATABASE_URL") or os.environ.get("DATABASE_URL") or "").strip()


class FindingStore:
    """MOMUS's vulnerability corpus. SQLite by default, Postgres when a DSN is configured."""

    def __init__(self, data_dir: str = "data", *, dsn: str | None = None, sqlite_path: str | None = None):
        self._dsn = dsn if dsn is not None else database_url()
        self.backend = "postgres" if self._dsn else "sqlite"
        self._pg = None
        if self.backend == "postgres":
            try:
                import psycopg  # noqa: F401  (psycopg3)
                self._pg = "psycopg"
            except ImportError:
                try:
                    import psycopg2  # noqa: F401
                    self._pg = "psycopg2"
                except ImportError:
                    # No driver → degrade to SQLite rather than losing the corpus entirely.
                    self.backend = "sqlite"
                    self._dsn = ""
        self._path = sqlite_path or os.path.join(data_dir, "findings.db")
        if self.backend == "sqlite":
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        self._init_schema()

    # ── connections ─────────────────────────────────────────────────────────
    @contextmanager
    def _conn(self) -> Iterator[Any]:
        if self.backend == "sqlite":
            con = sqlite3.connect(self._path, timeout=10)
            con.row_factory = sqlite3.Row
            try:
                con.execute("PRAGMA journal_mode=WAL")   # concurrent readers while we write
                con.execute("PRAGMA foreign_keys=ON")
                yield con
                con.commit()
            finally:
                con.close()
        else:
            if self._pg == "psycopg":
                import psycopg
                with psycopg.connect(self._dsn) as con:
                    yield con
            else:
                import psycopg2
                import psycopg2.extras
                con = psycopg2.connect(self._dsn)
                try:
                    yield con
                    con.commit()
                finally:
                    con.close()

    def _init_schema(self) -> None:
        ddl = _SQLITE_SCHEMA if self.backend == "sqlite" else _PG_SCHEMA
        with self._conn() as con:
            if self.backend == "sqlite":
                con.executescript(ddl)
            else:
                cur = con.cursor()
                for stmt in [s.strip() for s in ddl.split(";") if s.strip()]:
                    cur.execute(stmt)

    def _ph(self) -> str:
        """Parameter placeholder for the active backend."""
        return "?" if self.backend == "sqlite" else "%s"

    # ── writes ──────────────────────────────────────────────────────────────
    def record_finding(self, finding: Finding, *, scan_id: str | None = None) -> dict[str, Any]:
        """Insert a finding, or bump its seen_count if this bug is already known.

        Returns {"new": bool, "seen_count": int} — the caller (and the panel) can tell a fresh
        discovery from a rediscovery, which is exactly the memory an auditor needs.
        """
        doc = json.dumps(asdict(finding), ensure_ascii=False)
        dedup = finding.dedup_key or finding.compute_dedup_key()
        now = _now_z()
        p = self._ph()
        with self._conn() as con:
            cur = con.cursor()
            cur.execute(f"SELECT finding_id, seen_count FROM findings WHERE dedup_key = {p}", (dedup,))
            row = cur.fetchone()
            if row is not None:
                existing_id = row[0] if not isinstance(row, sqlite3.Row) else row["finding_id"]
                seen = (row[1] if not isinstance(row, sqlite3.Row) else row["seen_count"]) + 1
                cur.execute(
                    f"UPDATE findings SET seen_count = {p}, last_seen_at = {p}, scan_id = {p} "
                    f"WHERE dedup_key = {p}",
                    (seen, now, scan_id, dedup))
                return {"new": False, "seen_count": seen, "finding_id": existing_id}
            cur.execute(
                f"""INSERT INTO findings (finding_id, dedup_key, target, target_kind, probe, category,
                        severity, outcome, status, title, detail, scanner_pubkey, created_at,
                        first_seen_at, last_seen_at, seen_count, scan_id, doc)
                    VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},1,{p},{p})""",
                (finding.finding_id, dedup, finding.target, finding.target_kind, finding.probe,
                 finding.category, finding.severity, finding.outcome, finding.status, finding.title,
                 finding.detail, finding.scanner_pubkey, finding.created_at, now, now, scan_id, doc))
            return {"new": True, "seen_count": 1, "finding_id": finding.finding_id}

    def record_verdict(self, verdict: Any) -> None:
        """Persist an independent verifier's verdict. Idempotent per (finding, verifier, verdict)."""
        d = asdict(verdict) if not isinstance(verdict, dict) else verdict
        p = self._ph()
        sql = (f"INSERT INTO verdicts (finding_id, verdict, method, score, verifier_id, "
               f"verifier_pubkey, created_at, doc) VALUES ({p},{p},{p},{p},{p},{p},{p},{p})")
        sql += " ON CONFLICT DO NOTHING" if self.backend == "postgres" else ""
        args = (d.get("finding_id"), d.get("verdict"), d.get("method"), float(d.get("score") or 0),
                d.get("verifier_id"), d.get("verifier_pubkey"), d.get("created_at") or _now_z(),
                json.dumps(d, ensure_ascii=False))
        with self._conn() as con:
            cur = con.cursor()
            try:
                cur.execute(sql, args)
            except (sqlite3.IntegrityError, Exception) as exc:  # noqa: BLE001
                if isinstance(exc, sqlite3.IntegrityError):
                    return  # already recorded — fine
                if self.backend == "sqlite":
                    raise

    def set_status(self, finding_id: str, status: str) -> None:
        p = self._ph()
        with self._conn() as con:
            con.cursor().execute(
                f"UPDATE findings SET status = {p}, last_seen_at = {p} WHERE finding_id = {p}",
                (status, _now_z(), finding_id))

    def record_scan(self, report: Any) -> None:
        p = self._ph()
        rd = report.to_dict() if hasattr(report, "to_dict") else report
        sql = (f"INSERT INTO scans (scan_id, started_at, finished_at, targets, provider, counts) "
               f"VALUES ({p},{p},{p},{p},{p},{p})")
        sql += " ON CONFLICT DO NOTHING" if self.backend == "postgres" else " ON CONFLICT DO NOTHING"
        with self._conn() as con:
            try:
                con.cursor().execute(sql, (rd["scan_id"], rd["started_at"], rd["finished_at"],
                                           json.dumps(rd["targets"]), rd.get("provider"),
                                           json.dumps(rd["counts"])))
            except sqlite3.IntegrityError:
                pass

    # ── reads ───────────────────────────────────────────────────────────────
    def recent(self, limit: int = 50, *, severity: str | None = None, target: str | None = None,
               status: str | None = None) -> list[dict[str, Any]]:
        p = self._ph()
        where, args = [], []
        if severity:
            where.append(f"severity = {p}"); args.append(severity)
        if target:
            where.append(f"target = {p}"); args.append(target)
        if status:
            where.append(f"status = {p}"); args.append(status)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        args.append(int(max(1, min(limit, 500))))
        with self._conn() as con:
            cur = con.cursor()
            cur.execute(f"SELECT doc, seen_count, first_seen_at, last_seen_at FROM findings"
                        f"{clause} ORDER BY last_seen_at DESC LIMIT {p}", tuple(args))
            out = []
            for row in cur.fetchall():
                doc = row[0] if not isinstance(row, sqlite3.Row) else row["doc"]
                d = json.loads(doc)
                d["seen_count"] = row[1] if not isinstance(row, sqlite3.Row) else row["seen_count"]
                d["first_seen_at"] = row[2] if not isinstance(row, sqlite3.Row) else row["first_seen_at"]
                d["last_seen_at"] = row[3] if not isinstance(row, sqlite3.Row) else row["last_seen_at"]
                out.append(d)
            return out

    def get(self, finding_id: str) -> dict[str, Any] | None:
        p = self._ph()
        with self._conn() as con:
            cur = con.cursor()
            cur.execute(f"SELECT doc FROM findings WHERE finding_id = {p}", (finding_id,))
            row = cur.fetchone()
            if row is None:
                return None
            return json.loads(row[0] if not isinstance(row, sqlite3.Row) else row["doc"])

    def seen_before(self, dedup_key: str) -> int:
        """How many times this exact bug has been seen (0 = never)."""
        p = self._ph()
        with self._conn() as con:
            cur = con.cursor()
            cur.execute(f"SELECT seen_count FROM findings WHERE dedup_key = {p}", (dedup_key,))
            row = cur.fetchone()
            return int(row[0]) if row else 0

    def stats(self) -> dict[str, Any]:
        with self._conn() as con:
            cur = con.cursor()
            cur.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
            by_sev = {str(r[0]): int(r[1]) for r in cur.fetchall()}
            cur.execute("SELECT status, COUNT(*) FROM findings GROUP BY status")
            by_status = {str(r[0]): int(r[1]) for r in cur.fetchall()}
            cur.execute("SELECT COUNT(*) FROM findings")
            total = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM findings WHERE seen_count > 1")
            recurring = int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM scans")
            scans = int(cur.fetchone()[0])
        return {"backend": self.backend, "total_findings": total, "recurring": recurring,
                "by_severity": by_sev, "by_status": by_status, "scans": scans}
