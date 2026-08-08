import { Component, lazy, ReactNode, Suspense, useCallback, useRef } from "react";

import { useI18n } from "../i18n";

/* Hero — name, tagline, the 3D cosmic eye stage, and the two CTAs.
 *
 * The visual is MOMUS's signature R3F scene (the unblinking eye) rendered on the
 * ecosystem's shared CosmicCanvas. It is code-split: the landing copy paints
 * immediately and three.js arrives in its own chunk. If WebGL is unavailable or
 * the scene throws, we fall back to a pure-CSS eye so the hero never goes blank.
 */

const EyeStage = lazy(() => import("./EyeStage"));

class StageBoundary extends Component<{ children: ReactNode; fallback: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}

/** Procedural CSS stand-in: no WebGL, no canvas, still an eye. */
function StageFallback() {
  return <div className="momus-stage-fallback" aria-hidden="true" />;
}

export function Hero({ onLaunch }: { onLaunch: () => void }) {
  const { t } = useI18n();
  const tickerRef = useRef<HTMLSpanElement | null>(null);

  // The scene reports each probe verdict; we write it straight into the DOM so a
  // ~0.7 Hz ticker never triggers a React re-render.
  const onVerdict = useCallback((text: string, kind: "held" | "finding") => {
    const el = tickerRef.current;
    if (!el) return;
    el.textContent = text;
    el.className = kind === "finding" ? "hero-ticker-val finding" : "hero-ticker-val held";
  }, []);

  return (
    <section className="hero" id="top">
      <div className="hero-grid">
        <div className="hero-copy">
          <div className="eyebrow">
            <span className="pulse-dot" />{" "}
            {t("hero.eyebrow", undefined, "adversarial-audit satellite · red team")}
          </div>
          <h1 className="wordmark">MOMUS</h1>
          <p className="tagline">
            {t("hero.tagline_lead", undefined, "The auditor that finds the flaw and")}{" "}
            <em>{t("hero.tagline_signs_evidence", undefined, "signs the evidence")}</em>.
          </p>
          <p className="lede">
            {t("hero.lede_myth_lead", undefined, "Momus, god of blame, demanded a")}{" "}
            <strong>{t("hero.lede_myth_window", undefined, "window in the chest")}</strong>{" "}
            {t("hero.lede_myth_tail", undefined, "so any being's thoughts could be inspected.")}{" "}
            {t(
              "hero.lede_window_for_ecosystem",
              undefined,
              "MOMUS is that window for the ecosystem — an autonomous red team that probes our own components, then emits Ed25519-signed findings anyone can verify.",
            )}{" "}
            {t("hero.lede_complement_lead", undefined, "It is the offensive complement to")}{" "}
            <strong>ARGUS</strong> {t("hero.lede_complement_tail", undefined, "(defense).")}
          </p>
          <p className="creed">{t("hero.creed", undefined, "verify, don’t trust.")}</p>
          <div className="hero-cta">
            <button className="btn btn-primary" onClick={onLaunch}>
              {t("hero.cta_open_panel", undefined, "Open live panel")}
            </button>
            <a className="btn btn-ghost" href="#what">
              {t("hero.cta_how_it_works", undefined, "How it works")}
            </a>
          </div>
        </div>
        <div className="hero-visual">
          <div className="momus-stage">
            <StageBoundary fallback={<StageFallback />}>
              <Suspense fallback={<StageFallback />}>
                <EyeStage onVerdict={onVerdict} />
              </Suspense>
            </StageBoundary>
          </div>
          <div className="hero-visual-caption">
            {t("hero.visual_caption", undefined, "unblinking · scanning · signing")}
          </div>
          <div className="hero-ticker" aria-hidden="true">
            <span className="hero-ticker-key">{t("hero.ticker_label", undefined, "probe")}</span>
            <span ref={tickerRef} className="hero-ticker-val held">
              {t("hero.ticker_arming", undefined, "arming scanner…")}
            </span>
          </div>
        </div>
      </div>
    </section>
  );
}
