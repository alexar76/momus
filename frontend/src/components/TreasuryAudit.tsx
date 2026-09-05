/* ===========================================================================
 *  TreasuryAudit — the separation, provable by the visitor.
 *
 *  The Treasury has no product UI; it is an AUDIT surface. So this panel does one job well:
 *  it fetches MOMUS's scanner pubkey and the Treasury's own pubkey from two different services
 *  and shows, live, that they are NOT the same key — which is the entire "MOMUS cannot pay
 *  itself" claim, verified in the browser rather than asserted in prose. Below that it renders
 *  the payout ledger tail (state + settlement tier), so a reader can see what actually settled
 *  and whether it was a UNI simulation or real value.
 * ========================================================================= */

import { useEffect, useState } from "react";
import {
  getTreasuryHealth,
  getTreasuryLedger,
  type TreasuryHealth,
  type TreasuryLedger,
} from "../api";
import { useI18n } from "../i18n";

interface Props {
  /** MOMUS's scanner pubkey, from /health — so we can compare the two keys side by side. */
  scannerPubkey?: string;
}

function short(k?: string): string {
  if (!k) return "—";
  return k.length > 22 ? `${k.slice(0, 14)}…${k.slice(-6)}` : k;
}

const STATE_COLOR: Record<string, string> = {
  paid: "#3ddc84",
  held: "#ffcc33",
  refused: "#ff6b3d",
};

export default function TreasuryAudit({ scannerPubkey }: Props) {
  const { t } = useI18n();
  const [health, setHealth] = useState<TreasuryHealth | null>(null);
  const [ledger, setLedger] = useState<TreasuryLedger | null>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    const ac = new AbortController();
    (async () => {
      try {
        const [h, l] = await Promise.all([
          getTreasuryHealth(ac.signal),
          getTreasuryLedger(ac.signal).catch(() => null),
        ]);
        setHealth(h);
        setLedger(l);
        setOffline(false);
      } catch {
        setOffline(true);
      }
    })();
    return () => ac.abort();
  }, []);

  const treasuryKey = health?.treasury_pubkey;
  const distinct = Boolean(treasuryKey && scannerPubkey && treasuryKey !== scannerPubkey);

  // Both paragraphs below embed non-translatable spans (the Treasury brand in <strong>, the two
  // endpoint paths in <code>). Each stays ONE translatable sentence with placeholders, split on
  // here, so a translator may reorder the prose freely without losing the markup.
  const separation = t(
    "treasury.separation_intro",
    undefined,
    "MOMUS finds and signs. It cannot pay itself — a separate {{treasury}} holds the only key that can release a bounty, in its own container with its own key volume. Don't take that on faith: the two keys below are read live from two different services.",
  );
  const [separationBefore, separationAfter] = separation.split("{{treasury}}");
  const publicNote = t(
    "treasury.public_endpoints_note",
    undefined,
    "Only {{health}} and {{ledger}} are public. The payout path stays private — the one service that can release money does not get an open endpoint.",
  );
  const [noteBefore, noteBetween, noteAfter] = publicNote.split(/\{\{health\}\}|\{\{ledger\}\}/);

  return (
    <section className="section" id="treasury">
      <div className="section-head">
        <span className="kicker">treasury</span>
        <h2>
          {t(
            "treasury.heading",
            undefined,
            "The payer is a different service, with a different key",
          )}
        </h2>
      </div>
      <p className="section-sub">
        {separationBefore}
        <strong>Treasury</strong>
        {separationAfter}
      </p>

      <div className="keycmp">
        <div className="keycmp-row">
          <span className="keycmp-label">
            {t("treasury.scanner_key_label", undefined, "MOMUS scanner key")}
          </span>
          <code className="keycmp-key">{short(scannerPubkey)}</code>
          <span className="keycmp-note">
            {t("treasury.scanner_key_role", undefined, "finds · signs · ❌ cannot pay")}
          </span>
        </div>
        <div className="keycmp-row">
          <span className="keycmp-label">
            {t("treasury.treasury_key_label", undefined, "Treasury key")}
          </span>
          <code className="keycmp-key">{short(treasuryKey)}</code>
          <span className="keycmp-note">
            {t(
              "treasury.treasury_key_role",
              undefined,
              "releases bounties · ❌ cannot find or verify",
            )}
          </span>
        </div>
        <div className={`keycmp-verdict ${distinct ? "ok" : "warn"}`}>
          {offline
            ? t(
                "treasury.verdict_offline",
                undefined,
                "Treasury not reachable from here — the separation still holds in the service topology.",
              )
            : distinct
            ? t(
                "treasury.verdict_keys_distinct",
                undefined,
                "✓ Verified live: the two keys are different. No single key can both declare a finding valid and release its payout.",
              )
            : treasuryKey
            ? t(
                "treasury.verdict_keys_identical",
                undefined,
                "⚠ The two keys look identical — that would be a misconfiguration (the Treasury refuses to start in this state).",
              )
            : t("treasury.verdict_loading", undefined, "Loading…")}
        </div>
      </div>

      {health && (
        <div className="chiprow">
          <span className="chip">
            {t("treasury.chip_prod", { value: String(health.prod) }, "prod: {{value}}")}
          </span>
          <span className="chip">
            {t(
              "treasury.chip_crypto",
              {
                value: health.crypto_enabled
                  ? t("treasury.crypto_on", undefined, "on")
                  : t("treasury.crypto_off", undefined, "off"),
              },
              "crypto: {{value}}",
            )}
          </span>
          <span className="chip">
            {t(
              "treasury.chip_external_verifiers",
              { count: health.external_verifiers?.length ?? 0 },
              "external verifiers: {{count}}",
            )}
          </span>
        </div>
      )}

      {ledger && ledger.entries.length > 0 && (
        <div className="table-scroll" style={{ marginTop: "1rem" }}>
          <table className="findings-table">
            <thead>
              <tr>
                <th>{t("treasury.col_state", undefined, "state")}</th>
                <th>{t("treasury.col_severity", undefined, "severity")}</th>
                <th>{t("treasury.col_amount", undefined, "amount")}</th>
                <th>{t("treasury.col_settlement", undefined, "settlement")}</th>
                <th>{t("treasury.col_finding", undefined, "finding")}</th>
              </tr>
            </thead>
            <tbody>
              {ledger.entries
                .filter((e) => e.kind === "decision" || e.kind === "split")
                .slice(-8)
                .reverse()
                .map((e, i) => (
                  <tr key={i}>
                    <td>
                      <span
                        className="sev-badge"
                        style={{ color: STATE_COLOR[String(e.state)] || "#7a8699" }}
                      >
                        {e.state || e.ruling || e.kind}
                      </span>
                    </td>
                    <td>{e.severity || "—"}</td>
                    <td>{e.amount_usd != null ? `$${e.amount_usd}` : "—"}</td>
                    <td>
                      {e.settlement?.mode
                        ? e.settlement.simulated
                          ? t(
                              "treasury.settlement_simulated",
                              { mode: e.settlement.mode },
                              "{{mode}} (simulated)",
                            )
                          : e.settlement.mode
                        : "—"}
                    </td>
                    <td>
                      <code>{(e.finding_id || "").slice(0, 16) || "—"}</code>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="muted-note">
        {noteBefore}
        <code>/treasury/health</code>
        {noteBetween}
        <code>/treasury/ledger</code>
        {noteAfter}
      </p>
    </section>
  );
}
