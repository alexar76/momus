import { Component, ReactNode, useEffect, useState } from "react";
import { Hero } from "./components/Hero";
import { HowItWorks } from "./components/HowItWorks";
import { WhoPays } from "./components/WhoPays";
import { SelfLearning } from "./components/SelfLearning";
import { LLMChoice } from "./components/LLMChoice";
import { Footer } from "./components/Footer";
import { LivePanel } from "./components/LivePanel";
import TreasuryAudit from "./components/TreasuryAudit";
import { getHealth } from "./api";
import { useI18n } from "./i18n";

/* MOMUS — adversarial-audit satellite. A single SPA with two views wired to a
 * hash route (no router library): '#/live' shows the live scanner console,
 * everything else shows the landing page. */

type Route = "landing" | "live";

function routeFromHash(): Route {
  return window.location.hash.replace(/^#\/?/, "").toLowerCase() === "live" ? "live" : "landing";
}

/* The boundary is a class component and cannot hold a hook, so its fallback markup lives in this
 * one-line function component — same <div className="scene-error">, just translatable. */
function SceneError({ message }: { message: string }) {
  const { t } = useI18n();
  return <div className="scene-error">{t("nav.panel_error", { message }, "panel error: {{message}}")}</div>;
}

class ErrorBoundary extends Component<{ children: ReactNode }, { err: string | null }> {
  state = { err: null as string | null };
  static getDerivedStateFromError(e: any) {
    return { err: String(e?.message || e) };
  }
  render() {
    if (this.state.err)
      return <SceneError message={this.state.err} />;
    return this.props.children;
  }
}

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState<string>(() => {
    const saved = localStorage.getItem("momus-theme");
    if (saved === "light" || saved === "dark") return saved;
    return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
  });
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("momus-theme", theme);
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

export function App() {
  const [route, setRoute] = useState<Route>(routeFromHash);
  const [theme, toggleTheme] = useTheme();
  const { t } = useI18n();

  useEffect(() => {
    const onHash = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const go = (r: Route) => {
    window.location.hash = r === "live" ? "/live" : "/";
    setRoute(r);
    window.scrollTo({ top: 0, behavior: "auto" });
  };

  // MOMUS's scanner pubkey, so the Treasury panel can prove live that the two keys differ.
  // Best-effort: if the backend is unreachable the panel says so rather than claiming anything.
  const [scannerPubkey, setScannerPubkey] = useState<string | undefined>();
  useEffect(() => {
    const ac = new AbortController();
    getHealth(ac.signal)
      .then((h) => setScannerPubkey(h.scanner_pubkey))
      .catch(() => setScannerPubkey(undefined));
    return () => ac.abort();
  }, []);

  return (
    <div className="app">
      <header className="nav">
        <button
          className="nav-brand"
          onClick={() => go("landing")}
          aria-label={t("nav.brand_home_aria", undefined, "MOMUS home")}
        >
          <span className="nav-eye" aria-hidden="true">
            <span className="nav-eye-scan" />
          </span>
          <span className="nav-word">MOMUS</span>
        </button>
        <nav className="nav-links">
          <button className={route === "landing" ? "nav-link active" : "nav-link"} onClick={() => go("landing")}>
            {t("nav.overview", undefined, "Overview")}
          </button>
          <button className={route === "live" ? "nav-link active" : "nav-link"} onClick={() => go("live")}>
            {t("nav.live_panel", undefined, "Live panel")}
          </button>
          <a
            className="nav-link nav-external"
            href="https://github.com/alexar76/momus"
            target="_blank"
            rel="noreferrer noopener"
          >
            GitHub
          </a>
          <button
            className="theme-toggle"
            onClick={toggleTheme}
            aria-label={t("nav.theme_toggle_aria", undefined, "Toggle colour theme")}
            title={t("nav.theme_toggle_title", undefined, "Toggle theme")}
          >
            {theme === "dark" ? "☾" : "☀"}
          </button>
        </nav>
      </header>

      <main>
        {route === "live" ? (
          <ErrorBoundary>
            <LivePanel />
          </ErrorBoundary>
        ) : (
          <>
            <Hero onLaunch={() => go("live")} />
            <HowItWorks />
            <WhoPays />
            <ErrorBoundary>
              <TreasuryAudit scannerPubkey={scannerPubkey} />
            </ErrorBoundary>
            <SelfLearning />
            <LLMChoice />
          </>
        )}
      </main>

      <Footer />
    </div>
  );
}
