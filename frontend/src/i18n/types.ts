// Five languages, matching the docs. The monitor ships en/ru/es today; MOMUS ships the full set
// because its documentation does, and a landing in fewer languages than its own README reads as
// abandoned rather than scoped.
export const LOCALES = ['en', 'ru', 'es', 'fr', 'zh'] as const;
export type Locale = (typeof LOCALES)[number];

export const LOCALE_LABELS: Record<Locale, string> = {
  en: 'EN',
  ru: 'RU',
  es: 'ES',
  fr: 'FR',
  zh: '中文',
};

export type TranslationDict = Record<string, unknown>;
