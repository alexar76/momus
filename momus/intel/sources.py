"""Threat-intel feed sources — allowlisted, opt-in, fail-closed.

MOMUS fetches security reports ONLY from hosts on ``FEED_ALLOWLIST``. There is no
arbitrary-URL fetch path, exactly like GAIA's live-relay host allowlist: a feed that is not
listed here cannot be reached, so neither a config typo nor a distilled report can point MOMUS
at an attacker-chosen endpoint. Ingestion is off unless ``MOMUS_THREAT_INTEL=1``, and in
production (``AIFACTORY_PROD=1``) it stays off unless explicitly enabled.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

# Hosts MOMUS may fetch threat intel from. Everything else is refused before a socket opens.
FEED_ALLOWLIST = {
    "www.cisa.gov",           # CISA Known Exploited Vulnerabilities
    "services.nvd.nist.gov",  # NVD CVE API
    "api.osv.dev",            # OSV
    "api.github.com",         # GitHub Security Advisories (GHSA)
}


def _truthy(val: str | None) -> bool:
    return (val or "").strip().lower() in ("1", "true", "yes", "on")


def intel_enabled() -> bool:
    return _truthy(os.environ.get("MOMUS_THREAT_INTEL"))


@dataclass
class ThreatFeed:
    """One allowlisted feed. ``kind`` tells the distiller how to pre-parse the raw response."""

    feed_id: str
    url: str
    kind: str  # "cisa-kev" | "nvd" | "osv" | "ghsa" | "json" | "rss"

    def host_ok(self) -> bool:
        host = (urlparse(self.url).hostname or "").lower()
        return host in FEED_ALLOWLIST


# Ecosystem repos MOMUS watches for FRESH GitHub security advisories by default (overridable with
# MOMUS_INTEL_GITHUB_REPOS="owner/repo,owner/repo"). Public GHSA endpoints; no auth required,
# though a GITHUB_TOKEN raises the rate limit (added as a bearer header in fetch_raw).
_DEFAULT_GITHUB_REPOS = ["alexar76/momus", "alexar76/aicom"]


def default_feeds() -> list[ThreatFeed]:
    """The built-in feed set. Operators may add feeds via MOMUS_INTEL_FEEDS (id|url|kind, comma-
    separated) but ONLY hosts on FEED_ALLOWLIST survive the host_ok() filter."""
    feeds = [
        ThreatFeed("cisa-kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "cisa-kev"),
        ThreatFeed("osv", "https://api.osv.dev/v1/query", "osv"),
        # GitHub: the global advisory database (fresh CVEs/GHSAs) …
        ThreatFeed("ghsa-global", "https://api.github.com/advisories?per_page=25&type=reviewed", "ghsa"),
    ]
    # … plus fresh per-repo advisories for the ecosystem's own repos (and any the operator adds).
    repos = [r.strip() for r in (os.environ.get("MOMUS_INTEL_GITHUB_REPOS") or ",".join(_DEFAULT_GITHUB_REPOS)).split(",") if r.strip()]
    for repo in repos:
        if "/" in repo:
            feeds.append(ThreatFeed(f"ghsa:{repo}", f"https://api.github.com/repos/{repo}/security-advisories?per_page=25", "ghsa"))
    extra = os.environ.get("MOMUS_INTEL_FEEDS", "").strip()
    if extra:
        for spec in extra.split(","):
            parts = [p.strip() for p in spec.split("|")]
            if len(parts) == 3:
                feeds.append(ThreatFeed(parts[0], parts[1], parts[2]))
    return [f for f in feeds if f.host_ok()]


async def fetch_raw(feed: ThreatFeed, *, timeout_s: float = 15.0, max_items: int = 25) -> list[dict[str, Any]]:
    """Fetch a feed and return a bounded list of RAW report dicts. Never raises: a feed outage
    yields an empty list, never a crash and never a partial-but-unbounded ingest.

    The response is treated as untrusted data — bounded item count, and the distiller (not this
    function) decides what structured signal to keep."""
    if not feed.host_ok():
        return []
    headers: dict[str, str] = {}
    host = (urlparse(feed.url).hostname or "").lower()
    if host == "api.github.com":
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("MOMUS_GITHUB_TOKEN") or "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"  # optional: lifts the unauth rate limit
    try:
        async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=False, headers=headers) as client:
            if feed.kind == "osv":
                # OSV needs a query body; ask for a broad, recent ecosystem slice.
                r = await client.post(feed.url, json={"package": {"ecosystem": "PyPI", "name": "fastapi"}})
            else:
                r = await client.get(feed.url)
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError):
        return []
    items = _extract_items(feed.kind, data)
    return items[:max_items]


def _extract_items(kind: str, data: Any) -> list[dict[str, Any]]:
    """Pull a flat list of report dicts out of each feed's native shape. Structural only — no
    interpretation of any free text here."""
    if kind == "cisa-kev" and isinstance(data, dict):
        return [
            {"title": v.get("vulnerabilityName", ""), "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID','')}",
             "identifiers": [v.get("cveID", "")], "published": v.get("dateAdded", ""),
             "text": f"{v.get('shortDescription','')} product={v.get('product','')} vendor={v.get('vendorProject','')}"}
            for v in (data.get("vulnerabilities") or []) if isinstance(v, dict)
        ]
    if kind == "osv" and isinstance(data, dict):
        return [
            {"title": v.get("summary", v.get("id", "")), "url": (v.get("references") or [{}])[0].get("url", ""),
             "identifiers": [v.get("id", "")], "published": v.get("published", ""),
             "text": v.get("details", "")[:2000]}
            for v in (data.get("vulns") or []) if isinstance(v, dict)
        ]
    if kind == "ghsa" and isinstance(data, list):
        # GitHub advisories API returns a flat list of advisory objects (global or per-repo).
        return [
            {"title": v.get("summary", v.get("ghsa_id", "")),
             "url": v.get("html_url", v.get("url", "")),
             "identifiers": [i for i in (v.get("ghsa_id"), v.get("cve_id")) if i],
             "published": v.get("published_at", ""),
             "text": (v.get("description") or v.get("summary") or "")[:2000]}
            for v in data if isinstance(v, dict)
        ]
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)][:50]
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return [d for d in data["items"] if isinstance(d, dict)][:50]
    return []


def source_digest(item: dict[str, Any]) -> str:
    import json
    return "sha256-" + hashlib.sha256(
        json.dumps(item, sort_keys=True, default=str).encode()).hexdigest()
