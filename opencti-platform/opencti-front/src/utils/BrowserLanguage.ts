export const LANGUAGES: Record<string, string> = {
  AUTO: 'auto',
  CHINESE: 'zh-cn',
  ENGLISH: 'en-us',
  FRENCH: 'fr-fr',
  GERMAN: 'de-de',
  ITALIAN: 'it-it',
  JAPANESE: 'ja-jp',
  KOREAN: 'ko-kr',
  SPANISH: 'es-es',
};

export const DEFAULT_LANG: string = LANGUAGES.ENGLISH;
// These window.navigator contain language information
// 1. languages -> [] of preferred languages (eg ["en-US", "zh-CN", "ja-JP"]) Firefox^32, Chrome^32
// 2. language  -> Preferred language as String (eg "en-US") Firefox^5, IE^11, Safari,
//                 Chrome sends Browser UI language
// 3. browserLanguage -> UI Language of IE
// 4. userLanguage    -> Language of Windows Regional Options
// 5. systemLanguage  -> UI Language of Windows
const browserLanguagePropertyKeys = [
  'languages',
  'language',
  'browserLanguage',
  'userLanguage',
  'systemLanguage',
];

const availableLanguages: string[] = [
  LANGUAGES.CHINESE,
  LANGUAGES.ENGLISH,
  LANGUAGES.FRENCH,
  LANGUAGES.GERMAN,
  LANGUAGES.ITALIAN,
  LANGUAGES.JAPANESE,
  LANGUAGES.KOREAN,
  LANGUAGES.SPANISH,
];

interface NonStandardNavigator {
  browserLanguage?: string;
  userLanguage?: string;
  systemLanguage?: string;
}

export const detectedLocale = (navigatorInstance: (Partial<Navigator> & NonStandardNavigator) | null | undefined): string | undefined => {
  if (!navigatorInstance) return undefined;

  const nav = navigatorInstance as Record<string, string | string[] | undefined>;
  const languages = browserLanguagePropertyKeys
    .flatMap((key) => nav[key] ?? [])
    .map((x) => x.toLowerCase());

  return languages.find((x) => availableLanguages.includes(x));
};

export default detectedLocale(window.navigator) || DEFAULT_LANG; // If no locale is detected, fallback to 'en'
