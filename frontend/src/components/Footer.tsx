import { useI18n } from "../i18n";

/* Footer — links to GitHub and the ecosystem. */
export function Footer() {
  const { t } = useI18n();
  return (
    <footer className="footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <span className="footer-eye" aria-hidden="true">
            <span className="footer-eye-dot" />
          </span>
          <div>
            <strong>MOMUS</strong>
            <div className="footer-tag">{t("footer.tagline", undefined, "verify, don’t trust.")}</div>
          </div>
        </div>
        <nav className="footer-links">
          <a href="https://github.com/alexar76/momus" target="_blank" rel="noreferrer noopener">
            GitHub
          </a>
          <a href="https://github.com/alexar76/momus#readme" target="_blank" rel="noreferrer noopener">
            {t("footer.docs_link", undefined, "Docs")}
          </a>
          <a href="#top">{t("footer.back_to_top", undefined, "Back to top")}</a>
        </nav>
      </div>
      <div className="footer-fine">
        {t(
          "footer.mission_note",
          undefined,
          "Autonomous red team of the AIMarket ecosystem · offensive complement to ARGUS · findings are Ed25519-signed and independently verified before any bounty is released.",
        )}
      </div>
    </footer>
  );
}
