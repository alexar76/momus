/* "LLM choice" — the selectable cognition providers. */

import { useI18n } from "../i18n";

// `noteKey` carries the catalog key for the notes that are prose; the Anthropic note has none
// because "Claude" is a brand name and must render as itself in every locale.
const PROVIDERS = [
  {
    name: "DeepSeek V4 Pro",
    note: "prod default",
    noteKey: "llm.prod_default",
    kind: "hosted",
    flag: "default",
  },
  { name: "Anthropic", note: "Claude", kind: "hosted" },
  { name: "OpenAI-compatible", note: "any OAI API", noteKey: "llm.note_any_oai_api", kind: "hosted" },
  {
    name: "Metis",
    note: "ecosystem cognition",
    noteKey: "llm.note_ecosystem_cognition",
    kind: "ecosystem",
  },
  { name: "Ollama", note: "local", noteKey: "llm.note_local", kind: "local" },
  { name: "LM Studio", note: "local", noteKey: "llm.note_local", kind: "local" },
  {
    name: "Offline",
    note: "deterministic, no network",
    noteKey: "llm.note_deterministic_no_network",
    kind: "offline",
  },
];

export function LLMChoice() {
  const { t } = useI18n();
  // Both emphasised terms sit inside ONE translatable sentence (a translator may reorder it freely)
  // while the <strong> emphasis survives: the {{metis}} / {{offline}} placeholders are left
  // uninterpolated and split on here.
  const providers = t(
    "llm.intro_any_provider",
    undefined,
    "Point MOMUS at a hosted frontier model, a local runtime, or the ecosystem’s own {{metis}} tier — or run the {{offline}} mode with no network at all.",
  );
  const [beforeMetis, afterMetis = ""] = providers.split("{{metis}}");
  const [betweenTerms, afterOffline = ""] = afterMetis.split("{{offline}}");
  return (
    <section className="section" id="llm">
      <div className="section-head">
        <span className="kicker">{t("llm.kicker", undefined, "llm choice")}</span>
        <h2>{t("llm.heading", undefined, "Bring your own cognition")}</h2>
        <p className="section-sub">
          {t(
            "llm.intro_provider_agnostic",
            undefined,
            "The reasoning behind a probe is provider-agnostic.",
          )}{" "}
          {beforeMetis}
          <strong>Metis</strong>
          {betweenTerms}
          <strong>{t("llm.intro_offline_deterministic", undefined, "offline deterministic")}</strong>
          {afterOffline}
        </p>
      </div>
      <div className="provider-grid">
        {PROVIDERS.map((p) => (
          <div className={`provider-chip kind-${p.kind}`} key={p.name}>
            <span className="provider-name">{p.name}</span>
            <span className="provider-note">
              {p.noteKey ? t(p.noteKey, undefined, p.note) : p.note}
            </span>
            {p.flag === "default" && (
              <span className="provider-flag">{t("llm.prod_default", undefined, "prod default")}</span>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}
