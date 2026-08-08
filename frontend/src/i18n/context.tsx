import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import en from './locales/en.json';
import es from './locales/es.json';
import fr from './locales/fr.json';
import ru from './locales/ru.json';
import zh from './locales/zh.json';
import type { Locale, TranslationDict } from './types';
import { LOCALES } from './types';

// Same shape as the Alien Monitor's provider on purpose: one proven implementation, five catalogs,
// and a `t(key, vars, fallback)` whose fallback is the English string written at the call site — so a
// missing key degrades to readable English instead of printing the key path at a visitor.
const STORAGE_KEY = 'momus-locale';

const catalogs: Record<Locale, TranslationDict> = {
  en: en as TranslationDict,
  ru: ru as TranslationDict,
  es: es as TranslationDict,
  fr: fr as TranslationDict,
  zh: zh as TranslationDict,
};

function resolve(dict: TranslationDict, path: string): string | undefined {
  const parts = path.split('.');
  let cur: unknown = dict;
  for (const part of parts) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return typeof cur === 'string' ? cur : undefined;
}

function interpolate(template: string, vars?: Record<string, string | number>) {
  if (!vars) return template;
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => String(vars[key] ?? ''));
}

function detectLocale(): Locale {
  if (typeof window === 'undefined') return 'en';
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored && (LOCALES as readonly string[]).includes(stored)) return stored as Locale;
  const lang = (navigator.language || 'en').slice(0, 2).toLowerCase();
  return (LOCALES as readonly string[]).includes(lang) ? (lang as Locale) : 'en';
}

type I18nContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: string, vars?: Record<string, string | number>, defaultValue?: string) => string;
};

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(detectLocale);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    localStorage.setItem(STORAGE_KEY, next);
    document.documentElement.lang = next;
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  const t = useCallback(
    (key: string, vars?: Record<string, string | number>, defaultValue?: string) => {
      // English is the fallback catalog, and the call-site default is the last resort. A visitor
      // must never see a dotted key path.
      const hit = resolve(catalogs[locale], key) ?? resolve(catalogs.en, key) ?? defaultValue ?? key;
      return interpolate(hit, vars);
    },
    [locale],
  );

  const value = useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error('useI18n must be used inside <I18nProvider>');
  return ctx;
}
