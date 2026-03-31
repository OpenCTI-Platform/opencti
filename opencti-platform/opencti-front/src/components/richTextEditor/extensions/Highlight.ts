import HighlightBase from '@tiptap/extension-highlight';

/**
 * Legacy editor highlight class → color mapping.
 * Markers set background color, pens set text color (handled via CSS
 * for backward compat; not converted by this extension).
 */
export const LEGACY_HIGHLIGHT_MAP: Record<string, string> = {
  'marker-yellow': 'hsl(60, 75%, 60%)',
  'marker-green': 'hsl(120, 75%, 60%)',
  'marker-pink': 'hsl(345, 75%, 60%)',
  'marker-blue': 'hsl(201, 75%, 60%)',
};

/**
 * Extends TipTap's Highlight extension to parse legacy editor marker classes
 * (e.g. <mark class="marker-yellow">) and map them to a background color.
 * multicolor is always enabled.
 */
export const Highlight = HighlightBase.extend({
  parseHTML() {
    return [
      ...(this.parent?.() ?? []),
      // Accept legacy editor marker class marks
      ...Object.keys(LEGACY_HIGHLIGHT_MAP).map((cls) => ({
        tag: `mark.${cls}`,
        getAttrs: (node: HTMLElement) => ({
          color: LEGACY_HIGHLIGHT_MAP[cls] ?? null,
        }),
      })),
    ];
  },
}).configure({ multicolor: true });
