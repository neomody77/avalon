import en from './en.json';
import zh from './zh.json';

export const translations = { en, zh } as const;
export type Lang = keyof typeof translations;

export function t(lang: Lang, key: string): string {
  const keys = key.split('.');
  let result: any = translations[lang];
  for (const k of keys) {
    result = result?.[k];
  }
  return result ?? key;
}

export function getLangFromUrl(url: URL): Lang {
  const [, lang] = url.pathname.split('/');
  if (lang === 'zh') return 'zh';
  return 'en';
}

export function getAlternateUrl(url: URL, targetLang: Lang): string {
  const currentLang = getLangFromUrl(url);
  const pathname = url.pathname;

  if (targetLang === 'en') {
    return pathname.replace(/^\/zh/, '') || '/';
  } else {
    if (currentLang === 'en') {
      return `/zh${pathname === '/' ? '' : pathname}`;
    }
    return pathname;
  }
}
