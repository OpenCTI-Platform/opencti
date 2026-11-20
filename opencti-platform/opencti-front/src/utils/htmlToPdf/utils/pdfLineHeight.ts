const DEFAULT_FONT_SIZE_PT = 12;

const UNIT_TO_PT: Record<string, number> = {
  pt: 1,
  px: 0.75,
  cm: 28.3465,
  mm: 2.83465,
  in: 72,
};

const LENGTH = /^(-?\d*\.?\d+)(pt|px|cm|mm|in|r?em)$/i;
const STYLE_ATTRIBUTE = /(\sstyle\s*=\s*)(?:"([^"]*)"|'([^']*)')/gi;

const splitDeclaration = (declaration: string) => {
  const separator = declaration.indexOf(':');
  if (separator < 0) return null;
  return {
    property: declaration.slice(0, separator).trim().toLowerCase(),
    value: declaration.slice(separator + 1).trim(),
  };
};

/**
 * Size of an inline font-size in pt, or the pdfmake default.
 * Relative or keyword font sizes fall back to the default.
 */
const toFontSizePt = (fontSize: string | undefined) => {
  const match = fontSize?.match(LENGTH);
  if (!match) return DEFAULT_FONT_SIZE_PT;
  const unit = match[2].toLowerCase();
  const value = Number.parseFloat(match[1]);
  if (unit === 'em' || unit === 'rem') return value * DEFAULT_FONT_SIZE_PT;
  return value * UNIT_TO_PT[unit];
};

const normalizeStyle = (style: string) => {
  const declarations = style.split(';');
  const parsed = declarations.map(splitDeclaration);
  const fontSize = parsed.filter((entry) => entry?.property === 'font-size').pop()?.value;
  return declarations.flatMap((declaration, index) => {
    const entry = parsed[index];
    if (entry?.property !== 'line-height') return [declaration];
    const match = entry.value.match(LENGTH);
    if (!match) return [declaration];
    const unit = match[2].toLowerCase();
    const value = Number.parseFloat(match[1]);
    const ratio = unit === 'em' || unit === 'rem'
      ? value
      : (value * UNIT_TO_PT[unit]) / toFontSizePt(fontSize);
    if (!Number.isFinite(ratio) || ratio <= 0) return [];
    return [`line-height: ${Math.round(ratio * 100) / 100}`];
  }).join(';');
};

/**
 * pdfmake reads lineHeight as a multiplier of the font size, but html-to-pdfmake
 * converts a CSS line-height with a unit into points (12px becomes 9), which pdfmake
 * then applies as nine times the line spacing.
 * Rewrite every inline line-height with a unit into the unitless ratio CSS means,
 * computed against the font-size declared in the same style attribute.
 * Works on the style attributes of the string only: the content is never parsed as HTML.
 *
 * @param content The html content in string.
 * @returns Same content with unitless line-height values.
 */
const normalizeLineHeights = (content: string) => {
  if (!/line-height/i.test(content)) return content;
  return content.replace(STYLE_ATTRIBUTE, (attribute, prefix: string, doubleQuoted?: string, singleQuoted?: string) => {
    const quote = doubleQuoted !== undefined ? '"' : '\'';
    const style = doubleQuoted ?? singleQuoted ?? '';
    return /line-height/i.test(style) ? `${prefix}${quote}${normalizeStyle(style)}${quote}` : attribute;
  });
};

export default normalizeLineHeights;
