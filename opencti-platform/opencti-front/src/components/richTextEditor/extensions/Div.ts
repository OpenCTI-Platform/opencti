import { Node, mergeAttributes } from '@tiptap/core';

/**
 * TipTap node extension that preserves <div> elements from externally-created HTML.
 *
 * Without this extension TipTap (ProseMirror) has no schema node for <div>, so it
 * silently unwraps every <div> and discards its inline style / class attributes.
 * This means font-size, color and layout styles defined on parent divs are lost.
 *
 */
export const Div = Node.create({
  name: 'div',
  group: 'block',
  content: 'block+',
  defining: true,

  addAttributes() {
    return {
      style: {
        default: null,
        parseHTML: (element: HTMLElement) => element.getAttribute('style') || null,
        renderHTML: (attrs: Record<string, string | null>) => {
          if (!attrs.style) return {};
          return { style: attrs.style };
        },
      },
      class: {
        default: null,
        parseHTML: (element: HTMLElement) => element.getAttribute('class') || null,
        renderHTML: (attrs: Record<string, string | null>) => {
          if (!attrs.class) return {};
          return { class: attrs.class };
        },
      },
    };
  },

  parseHTML() {
    return [{ tag: 'div' }];
  },

  renderHTML({ HTMLAttributes }) {
    return ['div', mergeAttributes(HTMLAttributes), 0];
  },
});
