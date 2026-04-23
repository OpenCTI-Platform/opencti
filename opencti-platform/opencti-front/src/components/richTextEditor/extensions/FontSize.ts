import { FontSize as FontSizeBase } from '@tiptap/extension-text-style/font-size';
import { LEGACY_FONT_SIZE_MAP } from './TextStyle';

/**
 * Extends TipTap's FontSize to read font size from legacy editor classes when no
 * inline style is present. Must be used together with the extended TextStyle
 * (TextStyle.ts) which allows those spans to be parsed at all.
 */
export const FontSize = FontSizeBase.extend({
  addGlobalAttributes() {
    return [
      {
        types: ['textStyle'],
        attributes: {
          fontSize: {
            default: null,
            parseHTML: (element: HTMLElement) => {
              for (const [cls, size] of Object.entries(LEGACY_FONT_SIZE_MAP)) {
                if (element.classList.contains(cls)) return size;
              }
              return element.style.fontSize || null;
            },
            renderHTML: (attrs: Record<string, string>) => {
              if (!attrs.fontSize) return {};
              return { style: `font-size: ${attrs.fontSize}` };
            },
          },
        },
      },
    ];
  },
});
