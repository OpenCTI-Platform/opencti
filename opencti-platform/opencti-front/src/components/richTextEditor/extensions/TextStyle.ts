import { TextStyle as TextStyleBase } from '@tiptap/extension-text-style';

/**
 * CKEditor font-size class → pixel value mapping.
 * Shared with FontSize.ts to keep the two extensions in sync.
 */
export const CK_FONT_SIZE_MAP: Record<string, string> = {
  'text-tiny': '12px',
  'text-small': '10px',
  'text-big': '18px',
  'text-huge': '24px',
};

/**
 * Extends TipTap's TextStyle mark to also accept CKEditor font-size class
 * spans (e.g. <span class="text-big">). Without this, TextStyle rejects any
 * span that has no style attribute, so FontSize's addGlobalAttributes is
 * never reached for CKEditor class-only spans.
 */
export const TextStyle = TextStyleBase.extend({
  parseHTML() {
    return [
      ...(this.parent?.() ?? []),
      // Accept CKEditor font-size class spans (no inline style)
      ...Object.keys(CK_FONT_SIZE_MAP).map((cls) => ({
        tag: `span.${cls}`,
        consuming: false,
        getAttrs: () => ({}),
      })),
    ];
  },
});
