const DEFAULT_FONT_SIZE_PT = 12;

const UNIT_TO_PT: Record<string, number> = {
  pt: 1,
  px: 0.75,
  cm: 28.3465,
  mm: 2.83465,
  in: 72,
};

const LENGTH = /^(-?\d*\.?\d+)(pt|px|cm|mm|in|r?em)$/i;

/**
 * Size of the element's own inline font-size in pt, or the pdfmake default.
 * Relative or keyword font sizes fall back to the default.
 */
const getFontSizePt = (element: HTMLElement) => {
  const match = element.style.fontSize.trim().match(LENGTH);
  if (!match) return DEFAULT_FONT_SIZE_PT;
  const unit = match[2].toLowerCase();
  const value = Number.parseFloat(match[1]);
  if (unit === 'em' || unit === 'rem') return value * DEFAULT_FONT_SIZE_PT;
  return value * UNIT_TO_PT[unit];
};

/**
 * pdfmake reads lineHeight as a multiplier of the font size, but html-to-pdfmake
 * converts a CSS line-height with a unit into points (12px becomes 9), which pdfmake
 * then applies as nine times the line spacing.
 * Rewrite every inline line-height with a unit into the unitless ratio CSS means.
 *
 * @param content The html content in string.
 * @returns Same content with unitless line-height values.
 */
const normalizeLineHeights = (content: string) => {
  if (!/line-height/i.test(content)) return content;
  const container = document.createElement('div');
  container.innerHTML = content;
  container.querySelectorAll<HTMLElement>('[style]').forEach((element) => {
    const match = element.style.lineHeight.trim().match(LENGTH);
    if (!match) return;
    const unit = match[2].toLowerCase();
    const value = Number.parseFloat(match[1]);
    const ratio = unit === 'em' || unit === 'rem'
      ? value
      : (value * UNIT_TO_PT[unit]) / getFontSizePt(element);
    if (!Number.isFinite(ratio) || ratio <= 0) {
      element.style.removeProperty('line-height');
      return;
    }
    element.style.lineHeight = String(Math.round(ratio * 100) / 100);
  });
  return container.innerHTML;
};

export default normalizeLineHeights;
