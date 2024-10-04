import * as R from 'ramda';

export const LANGUAGES = {
  AUTO: 'auto',
  ENGLISH: 'en-us',
  FRENCH: 'fr-fr',
  SPANISH: 'es-es',
  JAPANESE: 'ja-jp',
  CHINESE: 'zh-cn',
  GERMAN: 'de-de',
  KOREAN: 'ko-kr',
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
  LANGUAGES.ENGLISH,
  LANGUAGES.FRENCH,
  LANGUAGES.SPANISH,
  LANGUAGES.JAPANESE,
  LANGUAGES.CHINESE,
  LANGUAGES.GERMAN,
  LANGUAGES.KOREAN,
];

const detectedLocale = R.pipe(
  R.pick(browserLanguagePropertyKeys), // Get only language properties
  R.values(), // Get values of the properties
  R.flatten(), // flatten all arrays
  R.reject(R.isNil), // Remove undefined values
  R.map((x) => x.toLowerCase()),
  R.find((x) => R.includes(x, availableLanguages)), // Returns first language matched in languages
);

// eslint-disable-next-line max-len
export default detectedLocale(window.navigator) || DEFAULT_LANG; // If no locale is detected, fallback to 'en'
