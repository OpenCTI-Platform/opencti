import { describe, it, expect, vi } from 'vitest';
import { FONTS, detectLanguage } from './pdfFonts';

vi.mock('../../../relay/environment', () => ({ APP_BASE_PATH: '' }));

describe('PDF fonts for Japanese and Korean content', () => {
  it.each(['こんにちは', '안녕하세요'])('provides fallback faces for italic text in %s', (text) => {
    const font = FONTS[detectLanguage(text)];
    expect(font.italics).toBe(font.normal);
    expect(font.bolditalics).toBe(font.bold);
  });
});
