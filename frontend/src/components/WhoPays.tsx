import { KeySeparationDiagram } from "./KeySeparationDiagram";
import { useI18n } from "../i18n";

/* "Who pays" — the structural reason MOMUS cannot pay itself. */

const GUARANTEES = [
  {
    titleKey: "pays.guarantee_scanner_key_only_title",
    bodyKey: "pays.guarantee_scanner_key_only_body",
    title: "Scanner key only",
    body: "MOMUS holds a single Ed25519 scanner key. It can sign a finding — it cannot sign a payout. /health surfaces holds_treasury_key:false so the separation is verifiable from outside.",
  },
  {
    titleKey: "pays.guarantee_independent_verification_title",
    bodyKey: "pays.guarantee_independent_verification_body",
    title: "Independent verification",
    body: "A finding pays out only after independent confirmation: ≥2 distinct verifier keys for high/critical, one of which must be a registered external verifier such as Metis.",
  },
  {
    titleKey: "pays.guarantee_anti_griefing_deposit_title",
    bodyKey: "pays.guarantee_anti_griefing_deposit_body",
    title: "Anti-griefing deposit",
    body: "Submitting for bounty requires a deposit, so flooding the queue with junk findings costs the sender — not the Treasury.",
  },
  {
    titleKey: "pays.guarantee_dedup_replay_guard_title",
    bodyKey: "pays.guarantee_dedup_replay_guard_body",
    title: "Dedup replay-guard",
    body: "A stable dedup_key is the identity of the bug, not the report. Rediscovering one flaw collapses to a single payable claim — you cannot get paid twice.",
  },
  {
    titleKey: "pays.guarantee_fail_closed_crypto_off_title",
    bodyKey: "pays.guarantee_fail_closed_crypto_off_body",
    title: "Fail-closed when crypto is off",
    body: "With the crypto master switch off, no settlement path exists. Payouts don't silently succeed — they simply cannot happen.",
  },
];

export function WhoPays() {
  const { t } = useI18n();
  return (
    <section className="section" id="who-pays">
      <div className="section-head">
        <span className="kicker">{t("pays.kicker_who_pays", undefined, "who pays")}</span>
        <h2>{t("pays.cannot_pay_itself_title", undefined, "MOMUS is structurally unable to pay itself")}</h2>
        <p className="section-sub">
          {t("pays.lede", undefined,
            "A red team that signs its own cheques is a fraud generator. So the role that FINDS and the role that PAYS are split across separate keys in separate containers — with independent verifiers wedged between them.")}
        </p>
      </div>

      <KeySeparationDiagram />

      <div className="guarantee-grid">
        {GUARANTEES.map((g) => (
          <div className="guarantee" key={g.title}>
            <h4>{t(g.titleKey, undefined, g.title)}</h4>
            <p>{t(g.bodyKey, undefined, g.body)}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
