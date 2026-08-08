/* "Self-learning" — allowlisted intel feeds + a UCB bandit over attack classes. */

import { useI18n } from "../i18n";

const CATS = [
  { c: "integrity", label: "integrity" },
  { c: "authz", label: "authz" },
  { c: "input-validation", label: "input-validation" },
  { c: "settlement", label: "settlement" },
  { c: "injection", label: "injection" },
  { c: "replay", label: "replay" },
  { c: "dos", label: "dos" },
];

export function SelfLearning() {
  const { t } = useI18n();
  return (
    <section className="section" id="learning">
      <div className="section-head">
        <span className="kicker">{t("learn.kicker", undefined, "self-learning")}</span>
        <h2>{t("learn.title", undefined, "It gets sharper every scan")}</h2>
        <p
          className="section-sub"
          dangerouslySetInnerHTML={{
            __html: t(
              "learn.intro",
              undefined,
              "MOMUS ingests public security reports from <strong>allowlisted feeds</strong> and learns from its own and its peers’ confirmed findings. A <strong>UCB bandit</strong> over attack-classes decides which probes to run first — spending effort where it has recently paid off, while still exploring the quiet corners.",
            ),
          }}
        />
      </div>

      <div className="learn-grid">
        <div className="learn-card">
          <h4>{t("learn.untrusted_data_title", undefined, "Untrusted data, never instructions")}</h4>
          <p
            dangerouslySetInnerHTML={{
              __html: t(
                "learn.untrusted_data_body",
                undefined,
                "Fetched reports are treated as <strong>data behind a prompt-firewall</strong>. A CVE write-up can teach MOMUS <em>which class</em> of bug to look for; it can never tell MOMUS what to do. Distillation maps each report to attack categories — nothing more.",
              ),
            }}
          />
          <div className="firewall-strip">
            <span className="fw-node fw-in">{t("learn.firewall_public_feed", undefined, "public feed")}</span>
            <span className="fw-arrow">▶</span>
            <span className="fw-node fw-wall">{t("learn.firewall_prompt_firewall", undefined, "prompt firewall")}</span>
            <span className="fw-arrow">▶</span>
            <span className="fw-node fw-out">{t("learn.firewall_category_signal", undefined, "category signal")}</span>
          </div>
        </div>

        <div className="learn-card">
          <h4>{t("learn.bandit_priority_title", undefined, "Bandit priority (illustrative)")}</h4>
          <p className="muted-note">
            {t(
              "learn.bandit_priority_note",
              undefined,
              "Higher score = probed sooner. Live values appear in the panel’s intelligence widget once the backend is reachable.",
            )}
          </p>
          <div className="mini-bars">
            {CATS.map((k, i) => {
              const v = 0.86 - i * 0.1;
              return (
                <div className="mini-bar-row" key={k.c}>
                  <span className={`cat-dot cat-${k.c}`} />
                  <span className="mini-bar-label">{k.label}</span>
                  <span className="mini-bar-track">
                    <span className="mini-bar-fill" style={{ width: `${Math.max(v, 0.08) * 100}%` }} />
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
