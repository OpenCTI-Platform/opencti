import { TableHeader as TiptapTableHeader } from '@tiptap/extension-table';

/**
 * Extended TableHeader that allows any block content and preserves inline width styles.
 */
export const NestedTableHeader = TiptapTableHeader.extend({
  content: 'block+',
  addAttributes() {
    return {
      ...this.parent?.(),
      width: {
        default: null,
        parseHTML: (element: HTMLElement) => {
          return element.style.width || element.getAttribute('width') || null;
        },
        renderHTML: (attributes) => {
          if (!attributes.width) {
            return {};
          }
          return {
            style: `width: ${attributes.width}`,
          };
        },
      },
    };
  },
});
