import * as R from 'ramda';

export const LANGUAGES = {
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

export const DEFAULT_LANG = LANGUAGES.ENGLISH;
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

const availableLanguages = [
  LANGUAGES.CHINESE,
  LANGUAGES.ENGLISH,
  LANGUAGES.FRENCH,
  LANGUAGES.GERMAN,
  LANGUAGES.ITALIAN,
  LANGUAGES.JAPANESE,
  LANGUAGES.KOREAN,
  LANGUAGES.SPANISH,
];

const detectedLocale = R.pipe(
  R.pick(browserLanguagePropertyKeys), // Get only language properties
  R.values(), // Get values of the properties
  R.flatten(), // flatten all arrays
  R.reject(R.isNil), // Remove undefined values
  R.map((x) => x.toLowerCase()),
  R.find((x) => R.includes(x, availableLanguages)), // Returns first language matched in languages
);

export default detectedLocale(window.navigator) || DEFAULT_LANG; // If no locale is detected, fallback to 'en'
