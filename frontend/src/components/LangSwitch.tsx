import { LOCALES, LOCALE_LABELS, useI18n } from "../i18n";

/** Five locales matching the docs — without this, a Russian browser lands on RU
 *  forever with no way out, which is how the landing looked unfinished. */
export function LangSwitch() {
  const { locale, setLocale, t } = useI18n();

  return (
    <div
      className="lang-switch"
      role="group"
      aria-label={t("nav.language", undefined, "Language")}
    >
      {LOCALES.map((code) => (
        <button
          key={code}
          type="button"
          className={locale === code ? "active" : undefined}
          aria-pressed={locale === code}
          onClick={() => setLocale(code)}
        >
          {LOCALE_LABELS[code]}
        </button>
      ))}
    </div>
  );
}
