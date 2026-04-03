import HighlightBase from '@tiptap/extension-highlight';

/**
 * Legacy editor highlight class → color mapping.
 * Markers set background color, pens set text color (handled via CSS
 * for backward compat; not converted by this extension).
 */
export const LEGACY_HIGHLIGHT_MAP: Record<string, string> = {
  'marker-yellow': 'rgb(255, 255, 0)',
  'marker-green': 'rgb(98, 249, 98)',
  'marker-pink': 'rgb(252, 120, 153)',
  'marker-blue': 'rgb(15, 188, 255)',
};

export const LEGACY_PEN_MAP: Record<string, string> = {
  'pen-red': 'rgb(231, 19, 19)',
  'pen-green': 'rgb(18, 138, 0)',
};

/**
 * Extends TipTap's Highlight extension to parse legacy editor marker classes
 * (e.g. <mark class="marker-yellow">) and map them to a background color.
 * multicolor is always enabled.
 */
export const Highlight = HighlightBase.extend({
  addAttributes() {
    return {
      ...this.parent?.(),
      class: {
        default: null,
        parseHTML: (element) => element.getAttribute('class') ?? null,
        renderHTML: (attributes) => {
          if (!attributes.class) {
            return {};
          }
          return { class: attributes.class };
        },
      },
    };
  },
  parseHTML() {
    return [
      ...(this.parent?.() ?? []),
      // Accept legacy editor marker class marks
      ...Object.keys(LEGACY_HIGHLIGHT_MAP).map((cls) => ({
        tag: `mark.${cls}`,
        getAttrs: (node: HTMLElement | string) => {
          const classAttr = typeof node === 'string' ? '' : node.getAttribute('class');
          return {
            color: LEGACY_HIGHLIGHT_MAP[cls] ?? null,
            class: classAttr,
          };
        },
      })),
      // Accept legacy editor pen class marks
      ...Object.keys(LEGACY_PEN_MAP).map((cls) => ({
        tag: `mark.${cls}`,
        getAttrs: (node: HTMLElement | string) => {
          const classAttr = typeof node === 'string' ? '' : node.getAttribute('class');
          return {
            color: 'transparent',
            class: classAttr,
          };
        },
      })),
    ];
  },
}).configure({ multicolor: true });
