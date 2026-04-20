import { TableCell as TiptapTableCell } from '@tiptap/extension-table';

/**
 * Extended TableCell that allows any block content including nested tables.
 * No nesting depth limit — the schema permits table > tableCell > table recursively.
 * Also preserves inline width styles from migration.
 */
export const NestedTableCell = TiptapTableCell.extend({
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
