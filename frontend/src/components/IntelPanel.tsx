import { Intel } from "../api";
import { useI18n } from "../i18n";

/* IntelPanel — the self-learning widget: category-score bars + recent cards. */
export function IntelPanel({ intel }: { intel: Intel | null }) {
  const { t } = useI18n();

  if (!intel) {
    return (
      <div className="empty-state">
        {t("intel.summary_unavailable", undefined, "Intelligence summary unavailable.")}
      </div>
    );
  }

  const scores = Object.entries(intel.category_scores || {});
  const max = Math.max(0.0001, ...scores.map(([, v]) => v));

  return (
    <div className="intel-panel">
      <div className="intel-meta">
        <span className={`chip ${intel.intel_enabled ? "chip-on" : "chip-off"}`}>
          {intel.intel_enabled
            ? t("intel.status_enabled", undefined, "intel enabled")
            : t("intel.status_offline", undefined, "intel offline")}
        </span>
        <span className="chip">{t("intel.cards_count", { n: intel.cards_total }, "cards {{n}}")}</span>
        <span className="chip">{t("intel.arms_count", { n: intel.learned_pairs }, "arms {{n}}")}</span>
        <span className="chip">
          {t("intel.provider_name", { name: intel.provider }, "provider {{name}}")}
        </span>
      </div>

      <div className="intel-cols">
        <div className="intel-col">
          <h4>{t("intel.category_scores_heading", undefined, "Bandit priority · category scores")}</h4>
          <p className="muted-note">{t("intel.category_scores_hint", undefined, "higher = probed sooner")}</p>
          {scores.length === 0 ? (
            <div className="empty-state small">
              {t("intel.no_category_scores", undefined, "No category scores yet.")}
            </div>
          ) : (
            <div className="score-bars">
              {scores.map(([cat, v]) => (
                <div className="score-row" key={cat}>
                  <span className={`cat-dot cat-${cat}`} />
                  <span className="score-label">{cat}</span>
                  <span className="score-track">
                    <span className={`score-fill cat-bg-${cat}`} style={{ width: `${(v / max) * 100}%` }} />
                  </span>
                  <span className="score-val mono">{v.toFixed(3)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="intel-col">
          <h4>{t("intel.recent_cards_heading", undefined, "Recent threat-intel cards")}</h4>
          {(!intel.recent_cards || intel.recent_cards.length === 0) ? (
            <div className="empty-state small">
              {t("intel.no_cards_ingested", undefined, "No cards ingested yet.")}
            </div>
          ) : (
            <ul className="card-list">
              {intel.recent_cards.map((c, i) => (
                <li key={`${c.url}-${i}`} className="intel-card-row">
                  <div className="intel-card-head">
                    <span className="intel-source">{c.source}</span>
                    {c.identifiers?.slice(0, 3).map((id) => (
                      <span className="intel-id mono" key={id}>
                        {id}
                      </span>
                    ))}
                  </div>
                  {c.url ? (
                    <a className="intel-title" href={c.url} target="_blank" rel="noreferrer noopener">
                      {c.title || c.url}
                    </a>
                  ) : (
                    <span className="intel-title">{c.title}</span>
                  )}
                  <div className="intel-cats">
                    {(c.mapped_categories || []).map((cat) => (
                      <span className={`cat-badge cat-${cat}`} key={cat}>
                        {cat}
                      </span>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
