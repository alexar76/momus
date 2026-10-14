import { useCallback, useEffect, useState } from "react";
import {
  Finding,
  Health,
  Intel,
  Providers,
  ScanReport,
  getFindings,
  getHealth,
  getIntel,
  getProviders,
  postScan,
  postSelfaudit,
  severityColor,
  API_BASE,
} from "../api";
import { FindingsTable } from "./FindingsTable";
import { IntelPanel } from "./IntelPanel";
import { useI18n } from "../i18n";

// ── illustrative static data, shown ONLY when the backend is unreachable ──────
const DEMO_FINDINGS: Finding[] = [
  {
    finding_id: "mom-demo0000000001",
    target: "oracle-family",
    target_kind: "oracle",
    probe: "free_tier_ceiling_bypass",
    category: "authz",
    severity: "high",
    outcome: "finding",
    title: "Free-tier ceiling served one invoke past quota",
    detail: "The metered node returned 200 on the (n+1)th unpaid call under a burst.",
    evidence: { status_code: 200, reproducer: "burst 6× free invoke; observe 6th 200" },
    dedup_key: "demo-authz-1",
    created_at: "2026-08-08T00:00:00Z",
    status: "raw",
    scanner_pubkey: "z6MkDEMOscannerkeyDEMODEMODEMODEMODEMOdemo",
    signature: { algorithm: "ed25519", value: "demo" },
  },
  {
    finding_id: "mom-demo0000000002",
    target: "hub",
    target_kind: "hub",
    probe: "receipt_signature_tamper",
    category: "integrity",
    severity: "info",
    outcome: "no_finding",
    title: "Tampered receipt correctly rejected",
    detail: "Mutated work-receipt failed verification, as required (fail-closed).",
    evidence: { status_code: 400, reproducer: "flip one byte in receipt.signature.value" },
    dedup_key: "demo-integrity-1",
    created_at: "2026-08-08T00:00:00Z",
    status: "confirmed",
    scanner_pubkey: "z6MkDEMOscannerkeyDEMODEMODEMODEMODEMOdemo",
    signature: { algorithm: "ed25519", value: "demo" },
  },
  {
    finding_id: "mom-demo0000000003",
    target: "settlement",
    target_kind: "hub",
    probe: "replay_settled_invoke",
    category: "replay",
    severity: "low",
    outcome: "inconclusive",
    title: "Replayed nonce needs a second observation",
    detail: "Duplicate-guard behaviour under clock skew was inconclusive on one run.",
    evidence: { status_code: 409, reproducer: "resend a settled invoke with same nonce" },
    dedup_key: "demo-replay-1",
    created_at: "2026-08-08T00:00:00Z",
    status: "raw",
    scanner_pubkey: "z6MkDEMOscannerkeyDEMODEMODEMODEMODEMOdemo",
    signature: { algorithm: "ed25519", value: "demo" },
  },
];

type Loading = "loading" | "ready" | "offline";

export function LivePanel() {
  const { t } = useI18n();
  const [state, setState] = useState<Loading>("loading");
  const [health, setHealth] = useState<Health | null>(null);
  const [providers, setProviders] = useState<Providers | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [intel, setIntel] = useState<Intel | null>(null);
  const [scanner, setScanner] = useState<string>("");

  const [target, setTarget] = useState<string>("self");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [reportKind, setReportKind] = useState<"scan" | "selfaudit" | null>(null);
  const [busy, setBusy] = useState<"" | "scan" | "selfaudit">("");
  const [actionError, setActionError] = useState<string>("");

  const loadAll = useCallback(async (signal?: AbortSignal) => {
    setState("loading");
    try {
      const h = await getHealth(signal); // gate on health — if this fails we go offline
      setHealth(h);
      setScanner(h.scanner_pubkey || "");
      // the rest are best-effort; a failure here shouldn't blank the panel
      const [p, f, it] = await Promise.allSettled([
        getProviders(signal),
        getFindings(50, signal),
        getIntel(signal),
      ]);
      if (p.status === "fulfilled") setProviders(p.value);
      if (f.status === "fulfilled") {
        setFindings(f.value.findings || []);
        if (f.value.scanner_pubkey) setScanner(f.value.scanner_pubkey);
      }
      if (it.status === "fulfilled") setIntel(it.value);
      setState("ready");
    } catch (e) {
      if ((e as any)?.name === "AbortError") return;
      setState("offline");
      setFindings(DEMO_FINDINGS);
    }
  }, []);

  useEffect(() => {
    const ac = new AbortController();
    loadAll(ac.signal);
    return () => ac.abort();
  }, [loadAll]);

  const refreshFindingsAndIntel = useCallback(async () => {
    try {
      const [f, it] = await Promise.allSettled([getFindings(50), getIntel()]);
      if (f.status === "fulfilled") setFindings(f.value.findings || []);
      if (it.status === "fulfilled") setIntel(it.value);
    } catch {
      /* non-fatal */
    }
  }, []);

  const runScan = useCallback(async () => {
    setBusy("scan");
    setActionError("");
    try {
      const r = await postScan(target);
      setReport(r);
      setReportKind("scan");
      await refreshFindingsAndIntel();
    } catch (e) {
      setActionError(
        t("live.error_scan_failed", { message: (e as Error).message }, "scan failed: {{message}}"),
      );
    } finally {
      setBusy("");
    }
  }, [target, refreshFindingsAndIntel, t]);

  const runSelfaudit = useCallback(async () => {
    setBusy("selfaudit");
    setActionError("");
    try {
      const r = await postSelfaudit();
      setReport(r);
      setReportKind("selfaudit");
      await refreshFindingsAndIntel();
    } catch (e) {
      setActionError(
        t(
          "live.error_selfaudit_failed",
          { message: (e as Error).message },
          "self-audit failed: {{message}}",
        ),
      );
    } finally {
      setBusy("");
    }
  }, [refreshFindingsAndIntel, t]);

  const targetOptions = ["self", ...(health?.targets || [])];
  const offline = state === "offline";
  // In production the control routes need an operator token, so the buttons are disabled with an
  // honest explanation rather than firing a request that comes back 403/404.
  const gated = Boolean(health?.control_gated);
  const disabled = offline || gated || busy !== "";

  return (
    <div className="live">
      <div className="live-head">
        <div>
          <span className="kicker">{t("live.kicker", undefined, "live panel")}</span>
          <h2>{t("live.title", undefined, "Scanner console")}</h2>
        </div>
        <div className="live-endpoint mono">{API_BASE || "same-origin"}</div>
      </div>

      {state === "loading" && (
        <div className="banner banner-info">
          {t("live.connecting", undefined, "Connecting to MOMUS backend…")}
        </div>
      )}
      {offline && (
        <div className="banner banner-warn">
          <strong>{t("live.offline_badge", undefined, "backend offline")}</strong> —{" "}
          {t(
            "live.offline_demo_note",
            undefined,
            "showing a static demo. The findings below are illustrative examples so the console is never blank; connect the MOMUS backend",
          )}
          {" ("}
          <code>{API_BASE || "same-origin"}</code>
          {") "}
          {t("live.offline_live_data_hint", undefined, "for live data.")}
        </div>
      )}

      {/* ── health strip ─────────────────────────────────────────────── */}
      <HealthStrip health={health} scanner={scanner} offline={offline} />

      {/* ── providers ────────────────────────────────────────────────── */}
      <ProvidersStrip providers={providers} />

      {gated && !offline && (
        <div className="banner banner-info">
          <strong>{t("live.readonly_badge", undefined, "read-only view")}</strong> —{" "}
          {t(
            "live.readonly_note",
            undefined,
            "this deployment is in production, so the scan and audit controls are operator-gated (and refused at the TLS edge). Everything you see below is live; launching a scan requires the operator token on the host. Run MOMUS locally to drive the console yourself.",
          )}
        </div>
      )}

      {/* ── controls ─────────────────────────────────────────────────── */}
      <div className="controls">
        <label className="control">
          <span>{t("live.target_label", undefined, "target")}</span>
          <select
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={disabled}
          >
            {targetOptions.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <button className="btn btn-primary" onClick={runScan} disabled={disabled}>
          {busy === "scan"
            ? t("live.btn_scanning", undefined, "scanning…")
            : t("live.btn_launch_scan", undefined, "Launch self-scan")}
        </button>
        <button className="btn btn-ghost" onClick={runSelfaudit} disabled={disabled}>
          {busy === "selfaudit"
            ? t("live.btn_auditing", undefined, "auditing…")
            : t("live.btn_run_selfaudit", undefined, "Run self-audit")}
        </button>
      </div>
      {actionError && <div className="banner banner-error">{actionError}</div>}

      {/* ── scan report ──────────────────────────────────────────────── */}
      {report && <ScanReportView report={report} kind={reportKind} />}

      {/* ── findings ledger ──────────────────────────────────────────── */}
      <div className="live-block">
        <h3>
          {t("live.signed_findings_title", undefined, "Signed findings")}{" "}
          <span className="count-pill">{findings.length}</span>
        </h3>
        <FindingsTable findings={findings} />
      </div>

      {/* ── intelligence ─────────────────────────────────────────────── */}
      <div className="live-block">
        <h3>{t("live.intel_title", undefined, "Intelligence · self-learning")}</h3>
        {offline ? (
          <div className="empty-state">
            {t("live.intel_offline", undefined, "Intelligence stream requires the live backend.")}
          </div>
        ) : (
          <IntelPanel intel={intel} />
        )}
      </div>
    </div>
  );
}

// ── health strip ──────────────────────────────────────────────────────────────
function HealthStrip({
  health,
  scanner,
  offline,
}: {
  health: Health | null;
  scanner: string;
  offline: boolean;
}) {
  const { t } = useI18n();
  const reachable = health?.provider?.reachable;
  return (
    <div className="health-strip">
      <Stat label={t("live.stat_service", undefined, "service")} value={health?.service || "momus"} />
      <Stat
        label={t("live.stat_version", undefined, "version")}
        value={health?.version || (offline ? "—" : "…")}
      />
      <Stat
        label={t("live.stat_provider", undefined, "provider")}
        value={
          health
            ? `${health.provider.provider} · ${health.provider.model}`
            : offline
            ? "—"
            : "…"
        }
        dot={reachable === undefined ? undefined : reachable ? "ok" : "bad"}
      />
      <Stat
        label={t("live.stat_crypto", undefined, "crypto")}
        value={
          health
            ? health.crypto_enabled
              ? t("live.crypto_enabled", undefined, "enabled")
              : t("live.crypto_off_fail_closed", undefined, "off (fail-closed)")
            : "—"
        }
        dot={health ? (health.crypto_enabled ? "ok" : "warn") : undefined}
      />
      <Stat
        label={t("live.stat_env", undefined, "env")}
        value={health ? (health.prod ? "prod" : "dev") : "—"}
      />
      <Stat
        label={t("live.stat_treasury_key_held", undefined, "treasury key held")}
        value={
          health
            ? health.holds_treasury_key
              ? t("live.treasury_key_yes", undefined, "YES ⚠")
              : t("live.treasury_key_no", undefined, "no ✓")
            : t("live.treasury_key_no", undefined, "no ✓")
        }
        dot={health?.holds_treasury_key ? "bad" : "ok"}
      />
      <Stat
        label={t("live.stat_scanner_key", undefined, "scanner key")}
        value={scanner ? truncKey(scanner) : "—"}
        mono
        title={scanner}
      />
    </div>
  );
}

function Stat({
  label,
  value,
  dot,
  mono,
  title,
}: {
  label: string;
  value: string;
  dot?: "ok" | "bad" | "warn";
  mono?: boolean;
  title?: string;
}) {
  return (
    <div className="stat" title={title}>
      <div className="stat-label">{label}</div>
      <div className={`stat-value${mono ? " mono" : ""}`}>
        {dot && <span className={`stat-dot dot-${dot}`} />}
        {value}
      </div>
    </div>
  );
}

// ── providers strip ───────────────────────────────────────────────────────────
function ProvidersStrip({ providers }: { providers: Providers | null }) {
  const { t } = useI18n();
  if (!providers) return null;
  const sel = providers.selected;
  return (
    <div className="providers-strip">
      <span className="providers-label">{t("live.providers_label", undefined, "providers")}</span>
      {providers.choices.map((c) => {
        const active = c.kind === sel.provider || c.name === sel.provider;
        return (
          <span
            key={c.name}
            className={`provider-tag${active ? " active" : ""} kind-${
              c.ecosystem ? "ecosystem" : c.local ? "local" : c.name === "offline" ? "offline" : "hosted"
            }`}
            title={`${c.kind} · ${c.default_model}${
              c.needs_key ? ` · ${t("live.provider_needs_key", undefined, "needs key")}` : ""
            }`}
          >
            {c.name}
            {active && <span className="sel-mark"> ●</span>}
          </span>
        );
      })}
    </div>
  );
}

// ── scan report ───────────────────────────────────────────────────────────────
function ScanReportView({
  report,
  kind,
}: {
  report: ScanReport;
  kind: "scan" | "selfaudit" | null;
}) {
  const { t } = useI18n();
  const c = report.counts || { probes: 0, findings: 0, no_finding: 0, inconclusive: 0 };
  return (
    <div className="live-block report-block">
      <h3>
        {kind === "selfaudit"
          ? t("live.selfaudit_report_title", undefined, "Self-audit report")
          : t("live.scan_report_title", undefined, "Scan report")}{" "}
        <span className="scan-id mono">{report.scan_id}</span>
      </h3>
      <div className="count-row">
        <Count n={c.probes} label={t("live.count_probes", undefined, "probes")} tone="neutral" />
        <Count
          n={c.findings}
          label={t("live.count_findings", undefined, "findings")}
          tone={c.findings > 0 ? "bad" : "ok"}
        />
        <Count n={c.no_finding} label={t("live.count_no_finding", undefined, "no finding")} tone="ok" />
        <Count
          n={c.inconclusive}
          label={t("live.count_inconclusive", undefined, "inconclusive")}
          tone="warn"
        />
      </div>
      {report.records?.length ? (
        <div className="table-scroll">
          <table className="records-table">
            <thead>
              <tr>
                <th>{t("live.col_target", undefined, "target")}</th>
                <th>{t("live.col_probe", undefined, "probe")}</th>
                <th>{t("live.col_outcome", undefined, "outcome")}</th>
                <th>{t("live.col_severity", undefined, "severity")}</th>
                <th>{t("live.col_title", undefined, "title")}</th>
              </tr>
            </thead>
            <tbody>
              {report.records.map((r, i) => {
                const isFinding = r.outcome === "finding";
                return (
                  <tr
                    key={`${r.probe}-${i}`}
                    className={isFinding ? "row-finding" : ""}
                    style={isFinding ? { borderLeft: `3px solid ${severityColor(String(r.severity))}` } : undefined}
                  >
                    <td className="mono">{r.target}</td>
                    <td className="mono probe-cell">{r.probe}</td>
                    <td>
                      <span className={`outcome-pill outcome-${r.outcome}`}>{r.outcome}</span>
                    </td>
                    <td>
                      {isFinding ? (
                        <span
                          className="sev-badge"
                          style={{
                            color: severityColor(String(r.severity)),
                            borderColor: severityColor(String(r.severity)),
                          }}
                        >
                          {r.severity}
                        </span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td className="title-cell">{r.title}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state small">
          {t("live.no_records", undefined, "No records in this report.")}
        </div>
      )}
    </div>
  );
}

function Count({ n, label, tone }: { n: number; label: string; tone: "ok" | "bad" | "warn" | "neutral" }) {
  return (
    <div className={`count count-${tone}`}>
      <span className="count-n">{n}</span>
      <span className="count-label">{label}</span>
    </div>
  );
}

function truncKey(s: string): string {
  if (!s) return "—";
  if (s.length <= 16) return s;
  return `${s.slice(0, 8)}…${s.slice(-6)}`;
}
