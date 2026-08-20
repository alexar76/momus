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

/** Render a translated string containing [[b]]…[[/b]] or [[em]]…[[/em]] as real emphasis.
 *
 * Why this exists: the alternative is splitting a sentence into three translated fragments around a
 * <strong>, which hands a translator a dangling "…demanded a" and locks every language into English
 * word order (and injects Latin spacing into CJK). One key per sentence, markup re-applied here.
 *
 * Deliberately NOT an HTML parser: it recognises exactly two marker pairs and emits React elements,
 * so a catalog entry — or a mistranslation — can never inject markup into the page.
 */
function Rich({ text }: { text: string }) {
  // [[b]]…[[/b]] rather than {{b}}…{{/b}}: the provider's interpolate() substitutes /\{\{(\w+)\}\}/,
  // so a brace marker is indistinguishable from a variable — it consumed {{b}} as an unknown var and
  // left the orphan {{/b}} rendering on the page. Brackets cannot collide with interpolation.
  const parts = text.split(/(\[\[(?:b|em)\]\].*?\[\[\/(?:b|em)\]\])/g);
  return (
    <>
      {parts.map((part, i) => {
        const m = /^\[\[(b|em)\]\](.*?)\[\[\/\1\]\]$/.exec(part);
        if (!m) return part;
        return m[1] === "b" ? <strong key={i}>{m[2]}</strong> : <em key={i}>{m[2]}</em>;
      })}
    </>
  );
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
            <Rich
              text={t("hero.tagline", undefined,
                "The auditor that finds the flaw and [[em]]signs the evidence[[/em]].")}
            />
          </p>
          <p className="lede">
            <Rich
              text={t("hero.lede_myth", undefined,
                "Momus, god of blame, demanded a [[b]]window in the chest[[/b]] so any being\u2019s thoughts could be inspected.")}
            />{" "}
            {t(
              "hero.lede_window_for_ecosystem",
              undefined,
              "MOMUS is that window for the ecosystem — an autonomous red team that probes our own components, then emits Ed25519-signed findings anyone can verify.",
            )}{" "}
            <Rich
              text={t("hero.lede_complement", { peer: "ARGUS" },
                "It is the offensive complement to [[b]]{{peer}}[[/b]] (defense).")}
            />
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
