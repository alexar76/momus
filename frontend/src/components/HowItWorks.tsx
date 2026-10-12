/* "What it does" — the safe, read-only adversarial probe classes. */

import { useI18n } from "../i18n";

const PROBES = [
  {
    tag: "authz",
    title: "Free-tier ceilings",
    body: "Pushes an oracle's free-tier limits to confirm the ceiling actually holds — that a metered capability can't be coaxed into serving beyond its unpaid quota.",
  },
  {
    tag: "integrity",
    title: "Manifest & receipt signatures",
    body: "Tampers with a copy of a manifest or work-receipt and checks that verification fails closed — a forged or mutated document must never validate.",
  },
  {
    tag: "settlement",
    title: "Settlement gates",
    body: "Attempts unpaid-serve, double-spend and out-of-order settlement against escrow gates to prove funds never move without a verified verdict.",
  },
  {
    tag: "injection",
    title: "Prompt-injection surfaces",
    body: "Feeds instruction-shaped payloads into LLM-backed nodes to confirm they treat fetched content as untrusted data, never as commands.",
  },
  {
    tag: "replay",
    title: "Freshness & replay",
    body: "Replays nonces and stale requests to check that duplicate-guards and freshness windows reject a re-sent, already-settled invocation.",
  },
  {
    tag: "dos",
    title: "Unbounded work",
    body: "Sends over-max and malformed shapes to confirm resource ceilings and input validation refuse work that would exhaust the node.",
  },
];

export function HowItWorks() {
  const { t } = useI18n();
  // The second sentence stays ONE translatable unit (a translator may reorder it freely) while the
  // <strong> emphasis survives: the {{finding}} placeholder is left uninterpolated and split on here.
  const proof = t(
    "how.intro_proof",
    undefined,
    "Every probe is non-destructive; every result is emitted as an {{finding}} with a reproducer, so the claim carries its own proof.",
  );
  const [proofBefore, proofAfter] = proof.split("{{finding}}");
  return (
    <section className="section" id="what">
      <div className="section-head">
        <span className="kicker">{t("how.kicker", undefined, "what it does")}</span>
        <h2>{t("how.heading", undefined, "Safe, read-only probes against our own components")}</h2>
        <p className="section-sub">
          {t(
            "how.intro_scope",
            undefined,
            "MOMUS attacks the ecosystem’s own oracles, hub and settlement paths — never third parties.",
          )}{" "}
          {proofBefore}
          <strong>{t("how.intro_signed_finding", undefined, "Ed25519-signed finding")}</strong>
          {proofAfter}
        </p>
      </div>
      <div className="card-grid">
        {PROBES.map((p) => (
          <article className="probe-card" key={p.title}>
            <span className={`cat-badge cat-${p.tag}`}>{p.tag}</span>
            <h3>{t(`how.probe_${p.tag}_title`, undefined, p.title)}</h3>
            <p>{t(`how.probe_${p.tag}_body`, undefined, p.body)}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
