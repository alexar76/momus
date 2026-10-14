import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Advisory,
  BULLETIN_FEEDS,
  BulletinState,
  getBulletin,
  severityColor,
} from "../api";
import { SeverityBadge } from "./FindingsTable";
import { useI18n } from "../i18n";

/* ===========================================================================
 *  Bulletin — MOMUS's own advisory record.
 *
 *  MOMUS ingests CISA KEV, OSV and GHSA and published nothing of its own. This page is the other
 *  half: the same shape we consume, so the tooling that reads the rest of the world reads us too.
 *
 *  The one rule this component must not get wrong is coordinated disclosure. MOMUS audits services WE
 *  OPERATE, so an entry with a working reproducer against an unfixed component is an attack script
 *  published under our own name. The backend already applies that rule — an `open` advisory arrives
 *  with reproducer === "" — and this component gates on `status` a SECOND time anyway. Not because the
 *  API is untrusted, but because the failure is unrecoverable: a reproducer rendered once has been
 *  fetched, and no later fix un-publishes it. Two cheap checks for one irreversible mistake.
 *
 *  What this component deliberately does NOT have is any way to ask for more. There is no "show
 *  full detail" toggle that re-fetches with a parameter, because no such parameter exists and
 *  inventing one would mean the page could request an exploit.
 * ========================================================================= */

const FIXED = "fixed";

/** ISO → the date, by slicing rather than by Date(): a stamp on the record must render identically in
 *  every timezone, and `new Date(...).toLocaleDateString()` would shift the day near midnight UTC. */
function day(stamp: string): string {
  return (stamp || "").slice(0, 10) || "—";
}

function truncMid(s: string, head = 10, tail = 8): string {
  if (!s) return "—";
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

export function Bulletin({ scannerPubkey }: { scannerPubkey?: string }) {
  const { t } = useI18n();
  const [state, setState] = useState<BulletinState | null>(null);

  useEffect(() => {
    const ac = new AbortController();
    getBulletin(ac.signal)
      .then(setState)
      .catch((e) => {
        if ((e as Error)?.name === "AbortError") return;
        setState({ kind: "offline", message: (e as Error).message });
      });
    return () => ac.abort();
  }, []);

  const advisories = state?.kind === "ready" ? state.index.advisories : [];
  const counts = useMemo(() => {
    const by = { open: 0, fixed: 0, withdrawn: 0 };
    for (const a of advisories) {
      // Anything not positively `fixed` or `withdrawn` counts as OPEN — the same fail-closed reading
      // the backend applies to an unknown status. A hole we cannot classify is not a closed one.
      if (a.status === FIXED) by.fixed += 1;
      else if (a.status === "withdrawn") by.withdrawn += 1;
      else by.open += 1;
    }
    return by;
  }, [advisories]);

  return (
    <div className="live bulletin">
      <div className="live-head">
        <div>
          <span className="kicker">{t("bulletin.kicker", undefined, "security bulletin")}</span>
          <h2>{t("bulletin.title", undefined, "Advisories")}</h2>
        </div>
        <div className="live-endpoint mono">MOMUS-YYYY-NNNN</div>
      </div>

      <p className="section-sub bulletin-lede">
        {t(
          "bulletin.lede",
          undefined,
          "MOMUS reads CISA KEV, OSV and GHSA. This is what it publishes back, in the same shape — so the same tooling can read us.",
        )}
      </p>

      <div className="banner banner-info">
        <strong>{t("bulletin.disclosure_badge", undefined, "coordinated disclosure")}</strong> —{" "}
        {t(
          "bulletin.disclosure_note",
          undefined,
          "An open advisory carries no reproducer, no evidence and no target. MOMUS audits services we operate, so a working reproducer for an unfixed hole would be an attack script published under our own name. A fixed advisory carries everything: it is a lesson now, not a weapon.",
        )}
      </div>

      <HeaderStrip
        counts={counts}
        total={advisories.length}
        state={state}
        scannerPubkey={scannerPubkey}
      />

      {state === null && (
        <div className="banner banner-info">
          {t("bulletin.loading", undefined, "Loading the bulletin…")}
        </div>
      )}

      {state?.kind === "disabled" && (
        <div className="empty-state">
          {t(
            "bulletin.empty_disabled",
            undefined,
            "This deployment does not publish a bulletin — advisory publishing is off, so there is no record here to read.",
          )}
        </div>
      )}

      {state?.kind === "offline" && (
        <div className="empty-state">
          {t(
            "bulletin.empty_offline",
            { message: state.message },
            "The bulletin could not be reached ({{message}}), so this page cannot tell you what is on the record — which is not the same as the record being empty.",
          )}
        </div>
      )}

      {state?.kind === "ready" && advisories.length === 0 && (
        <div className="empty-state">
          {t(
            "bulletin.empty_none",
            undefined,
            "MOMUS has published no advisories yet. An empty record means nothing has been published — not that nothing has been found.",
          )}
        </div>
      )}

      {advisories.length > 0 && <AdvisoryList advisories={advisories} />}
    </div>
  );
}

// ── header strip: counts, feeds, the key to pin ───────────────────────────────
function HeaderStrip({
  counts,
  total,
  state,
  scannerPubkey,
}: {
  counts: { open: number; fixed: number; withdrawn: number };
  total: number;
  state: BulletinState | null;
  scannerPubkey?: string;
}) {
  const { t } = useI18n();
  const ready = state?.kind === "ready";
  const signature = ready ? state.index.signature : "";
  const timestamp = ready ? state.index.timestamp : 0;

  return (
    <>
      <div className="count-row">
        <Count n={total} label={t("bulletin.count_total", undefined, "advisories")} tone="neutral" />
        <Count n={counts.open} label={t("bulletin.count_open", undefined, "open")} tone={counts.open > 0 ? "bad" : "ok"} />
        <Count n={counts.fixed} label={t("bulletin.count_fixed", undefined, "fixed")} tone="ok" />
        <Count
          n={counts.withdrawn}
          label={t("bulletin.count_withdrawn", undefined, "withdrawn")}
          tone="neutral"
        />
      </div>

      <div className="feed-strip">
        <span className="providers-label">{t("bulletin.feeds_label", undefined, "feeds")}</span>
        {/* Machine formats. Plain links, opened in a new tab: they are documents, not app routes. */}
        <a className="feed-link" href={BULLETIN_FEEDS.atom} target="_blank" rel="noreferrer noopener">
          Atom
        </a>
        <a className="feed-link" href={BULLETIN_FEEDS.osv} target="_blank" rel="noreferrer noopener">
          OSV
        </a>
        <a className="feed-link" href={BULLETIN_FEEDS.index} target="_blank" rel="noreferrer noopener">
          {t("bulletin.feed_index", undefined, "Signed index")}
        </a>
      </div>

      <div className="keycmp bulletin-pin">
        <div className="keycmp-row">
          <span className="keycmp-label">{t("bulletin.pin_label", undefined, "index key · pin this")}</span>
          <span className="keycmp-key">{scannerPubkey || "—"}</span>
        </div>
        <div className="keycmp-row">
          <span className="keycmp-label">{t("bulletin.signature_label", undefined, "index signature")}</span>
          <span className="keycmp-key mono">{signature ? truncMid(signature, 16, 12) : "—"}</span>
          {timestamp > 0 && (
            <span className="keycmp-note">
              {t("bulletin.signed_at", { when: new Date(timestamp).toISOString() }, "signed {{when}}")}
            </span>
          )}
        </div>
        <p className="keycmp-note">
          {t(
            "bulletin.pin_note",
            undefined,
            "The index is Ed25519-signed over the RFC 8785 canonical form of {advisories, timestamp} — the same envelope ARGUS's WARDEN already verifies, and the same key MOMUS signs its findings with. Fetch the signed index to check it yourself.",
          )}
        </p>
      </div>
    </>
  );
}

function Count({
  n,
  label,
  tone,
}: {
  n: number;
  label: string;
  tone: "ok" | "bad" | "warn" | "neutral";
}) {
  return (
    <div className={`count count-${tone}`}>
      <span className="count-n">{n}</span>
      <span className="count-label">{label}</span>
    </div>
  );
}

// ── the list ──────────────────────────────────────────────────────────────────
function AdvisoryList({ advisories }: { advisories: Advisory[] }) {
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const toggle = useCallback(
    (id: string) => setOpen((prev) => ({ ...prev, [id]: !prev[id] })),
    [],
  );
  return (
    <ul className="adv-list">
      {advisories.map((a) => (
        <AdvisoryRow key={a.id} advisory={a} expanded={!!open[a.id]} onToggle={() => toggle(a.id)} />
      ))}
    </ul>
  );
}

function StatusBadge({ status }: { status: string }) {
  const { t } = useI18n();
  // Fail closed on an unrecognised status: it renders as OPEN, never as fixed. The label a reader
  // sees must never be more reassuring than what we actually know.
  const kind = status === FIXED ? "fixed" : status === "withdrawn" ? "withdrawn" : "open";
  const label =
    kind === "fixed"
      ? t("bulletin.status_fixed", undefined, "fixed")
      : kind === "withdrawn"
      ? t("bulletin.status_withdrawn", undefined, "withdrawn")
      : t("bulletin.status_open", undefined, "open");
  return (
    <span className={`adv-status adv-status-${kind}`}>
      <span className="adv-status-dot" aria-hidden="true" />
      {label}
    </span>
  );
}

function AdvisoryRow({
  advisory,
  expanded,
  onToggle,
}: {
  advisory: Advisory;
  expanded: boolean;
  onToggle: () => void;
}) {
  const { t } = useI18n();
  const a = advisory;
  // THE gate. `status === "fixed"` and nothing else: not `reproducer !== ""`, because that would let
  // a reproducer that arrived by mistake decide its own disclosure.
  const disclosed = a.status === FIXED;
  const panelId = `adv-panel-${a.id}`;

  return (
    <li className="adv" style={{ borderLeftColor: severityColor(String(a.severity)) }}>
      <button
        className="adv-head"
        onClick={onToggle}
        aria-expanded={expanded}
        aria-controls={panelId}
      >
        <span className="adv-caret" aria-hidden="true">
          {expanded ? "▾" : "▸"}
        </span>
        <span className="adv-id mono">{a.id}</span>
        <StatusBadge status={String(a.status)} />
        <span className="adv-when mono">{day(a.published)}</span>
        <span className="adv-component mono">{a.component}</span>
        <SeverityBadge severity={String(a.severity)} />
        <span className="adv-summary">{a.summary}</span>
      </button>

      {expanded && (
        <div className="adv-body" id={panelId}>
          {/* The advisory states its own limits, so a screenshot of this panel cannot be mistaken
              for a full disclosure. Rendered from the STATUS rather than by printing the server's
              `disclosure` string, which is English-only and, for a fixed entry, is the single word
              "full" — unhelpful in any language. The server's exact wording stays one hover away, so
              nothing is hidden: the translation is a label, the raw string is the record. */}
          <p className="adv-disclosure" title={a.disclosure}>
            {disclosed
              ? t("bulletin.disclosure_line_fixed", undefined, "Full disclosure — this issue is fixed.")
              : a.status === "withdrawn"
              ? t(
                  "bulletin.disclosure_line_withdrawn",
                  undefined,
                  "Withdrawn — the entry stays on the record; the technical detail does not.",
                )
              : t(
                  "bulletin.disclosure_line_open",
                  undefined,
                  "Withheld pending a fix — no reproducer, no evidence, no target.",
                )}
          </p>

          <AdvBlock title={t("bulletin.details_heading", undefined, "Details")}>
            <p className="adv-text">{a.details}</p>
          </AdvBlock>

          {a.withdrawn_reason && (
            <AdvBlock title={t("bulletin.withdrawn_heading", undefined, "Why it was withdrawn")}>
              <p className="adv-text">{a.withdrawn_reason}</p>
            </AdvBlock>
          )}

          {/* Reproducer: `fixed` only. An open hole's is not here to be toggled — it never arrived. */}
          {disclosed && a.reproducer ? (
            <AdvBlock title={t("bulletin.reproducer_heading", undefined, "Reproducer")}>
              <pre className="adv-code">{a.reproducer}</pre>
            </AdvBlock>
          ) : (
            <AdvBlock title={t("bulletin.reproducer_heading", undefined, "Reproducer")}>
              <p className="adv-text muted">
                {a.status === "withdrawn"
                  ? t(
                      "bulletin.reproducer_withdrawn",
                      undefined,
                      "Withheld: MOMUS no longer stands behind this advisory, so it must not carry a working reproducer under MOMUS's signature.",
                    )
                  : t(
                      "bulletin.reproducer_withheld",
                      undefined,
                      "Withheld until a MOMUS-signed fixed verdict exists. This component is one we operate.",
                    )}
              </p>
            </AdvBlock>
          )}

          {disclosed && Object.keys(a.evidence || {}).length > 0 && (
            <AdvBlock title={t("bulletin.evidence_heading", undefined, "Evidence")}>
              <dl className="adv-kv">
                {Object.entries(a.evidence).map(([k, v]) => (
                  <div className="adv-kv-row" key={k}>
                    <dt>{k}</dt>
                    <dd className="mono">{String(v)}</dd>
                  </div>
                ))}
              </dl>
            </AdvBlock>
          )}

          {disclosed && Object.keys(a.gate_verdict || {}).length > 0 && (
            <AdvBlock title={t("bulletin.gate_heading", undefined, "Fix verdict")}>
              <dl className="adv-kv">
                {Object.entries(a.gate_verdict).map(([k, v]) => (
                  <div className="adv-kv-row" key={k}>
                    <dt>{k}</dt>
                    <dd className="mono">{String(v)}</dd>
                  </div>
                ))}
              </dl>
            </AdvBlock>
          )}

          {a.references.length > 0 && (
            <AdvBlock title={t("bulletin.references_heading", undefined, "References")}>
              <ul className="adv-refs">
                {a.references.map((r) => (
                  <li key={`${r.type}-${r.url}`}>
                    <span className="adv-ref-type">{r.type}</span>{" "}
                    <a href={r.url} target="_blank" rel="noreferrer noopener">
                      {r.url}
                    </a>
                  </li>
                ))}
              </ul>
            </AdvBlock>
          )}

          <div className="adv-meta mono">
            <span>{t("bulletin.meta_category", { value: a.category }, "category {{value}}")}</span>
            <span>{t("bulletin.meta_modified", { value: day(a.modified) }, "modified {{value}}")}</span>
            {a.finding_ids.length > 0 && (
              <span>
                {t(
                  "bulletin.meta_findings",
                  { count: a.finding_ids.length },
                  "{{count}} finding(s) on this bug",
                )}
              </span>
            )}
          </div>
        </div>
      )}
    </li>
  );
}

function AdvBlock({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="adv-block">
      <h4>{title}</h4>
      {children}
    </div>
  );
}
