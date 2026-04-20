import { TextStyle as TextStyleBase } from '@tiptap/extension-text-style';

/**
 * Legacy editor font-size class → pixel value mapping.
 * Shared with FontSize.ts to keep the two extensions in sync.
 */
export const LEGACY_FONT_SIZE_MAP: Record<string, string> = {
  'text-tiny': '0.7em',
  'text-small': '0.85em',
  'text-big': '1.4em',
  'text-huge': '1.8em',
};

/**
 * Extends TipTap's TextStyle mark to also accept legacy editor font-size class
 * spans (e.g. <span class="text-big">). Without this, TextStyle rejects any
 * span that has no style attribute, so FontSize's addGlobalAttributes is
 * never reached for legacy editor class-only spans.
 */
export const TextStyle = TextStyleBase.extend({
  parseHTML() {
    return [
      ...(this.parent?.() ?? []),
      // Accept legacy editor font-size class spans (no inline style)
      ...Object.keys(LEGACY_FONT_SIZE_MAP).map((cls) => ({
        tag: `span.${cls}`,
        consuming: false,
        getAttrs: () => ({}),
      })),
    ];
  },
});
