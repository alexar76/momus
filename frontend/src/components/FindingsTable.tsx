import { Finding, severityColor } from "../api";
import { useI18n } from "../i18n";

function trunc(s: string, head = 8, tail = 6): string {
  if (!s) return "—";
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const sev = String(severity || "info").toLowerCase();
  return (
    <span
      className="sev-badge"
      style={{ color: severityColor(sev), borderColor: severityColor(sev) }}
    >
      {sev}
    </span>
  );
}

/* FindingsTable — the signed-findings ledger. */
export function FindingsTable({ findings }: { findings: Finding[] }) {
  const { t } = useI18n();
  if (!findings.length) {
    return (
      <div className="empty-state">
        {t(
          "findings.empty_state",
          undefined,
          "No findings recorded yet. Launch a self-scan to populate the ledger.",
        )}
      </div>
    );
  }
  return (
    <div className="table-scroll">
      <table className="findings-table">
        <thead>
          <tr>
            <th>{t("findings.col_severity", undefined, "severity")}</th>
            <th>{t("findings.col_target", undefined, "target")}</th>
            <th>{t("findings.col_probe", undefined, "probe")}</th>
            <th>{t("findings.col_category", undefined, "category")}</th>
            <th>{t("findings.col_title", undefined, "title")}</th>
            <th>{t("findings.col_status", undefined, "status")}</th>
            <th>{t("findings.col_scanner_key", undefined, "scanner key")}</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.finding_id} style={{ borderLeft: `3px solid ${severityColor(String(f.severity))}` }}>
              <td>
                <SeverityBadge severity={String(f.severity)} />
              </td>
              <td className="mono">{f.target}</td>
              <td className="mono probe-cell">{f.probe}</td>
              <td>
                <span className={`cat-badge cat-${f.category}`}>{f.category}</span>
              </td>
              <td className="title-cell">
                {f.title}
                {f.detail && <span className="finding-detail">{f.detail}</span>}
              </td>
              <td>
                <span className={`status-pill status-${String(f.status).toLowerCase()}`}>{f.status}</span>
              </td>
              <td className="mono key-cell" title={f.scanner_pubkey}>
                {trunc(f.scanner_pubkey)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
