// Single source of truth for how static i18n keys are found in the front.
// Shared by extract-i18n-keyword.ts and verify-translation.ts so they never disagree.
const t_i18nPatternSource = String.raw`t_i18n\((['"])((?:\\.|(?!\1).)*)\1\s*[,)]`;
// Menu data (`*.entries.ts(x)` pages, navSections.tsx) declares its labels and search keywords as plain strings,
// translated at runtime with t_i18n(label) / t_i18n(keyword): there is no t_i18n('...') call to find in those files.
export const menuDataFilePattern = /(\.entries\.tsx?|navSections\.tsx)$/;
const menuLabelPatternSource = String.raw`\blabel:\s*(['"])((?:\\.|(?!\1).)*)\1`;
const menuKeywordsPattern = /\bkeywords:\s*\[([^\]]*)\]/g;
const stringLiteralPatternSource = String.raw`(['"])((?:\\.|(?!\1).)*)\1`;

// unescape the quote char that was escaped for JS syntax reasons only
const unescapeQuote = (quote: string, captured: string) => captured.replace(new RegExp(`\\\\${quote}`, 'g'), quote);

const collectStrings = (source: string, patternSource: string, keys: string[]) => {
  for (const [, quote, captured] of source.matchAll(new RegExp(patternSource, 'g'))) {
    const value = unescapeQuote(quote, captured);
    if (value) {
      keys.push(value);
    }
  }
};

export const extractFrontendKeys = (source: string): string[] => {
  const keys: string[] = [];
  collectStrings(source, t_i18nPatternSource, keys);
  return keys;
};

export const extractMenuKeys = (source: string): string[] => {
  const keys: string[] = [];
  collectStrings(source, menuLabelPatternSource, keys);
  for (const [, keywords] of source.matchAll(menuKeywordsPattern)) {
    collectStrings(keywords, stringLiteralPatternSource, keys);
  }
  return keys;
};
