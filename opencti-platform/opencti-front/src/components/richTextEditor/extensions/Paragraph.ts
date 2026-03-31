import { Paragraph as ParagraphBase } from '@tiptap/extension-paragraph';
import { mergeAttributes } from '@tiptap/core';

const INDENT_STEP = 40; // px, matches CKEditor default
const INDENT_MAX = 400; // px

declare module '@tiptap/core' {
  interface Commands<ReturnType> {
    indentation: {
      indent: () => ReturnType;
      outdent: () => ReturnType;
    };
  }
}

/**
 * Extends TipTap's Paragraph node to preserve margin-left inline style,
 * used by legacy editor to implement text indentation.
 * Also adds indent/outdent commands that increment/decrement margin-left by 40px.
 */
export const Paragraph = ParagraphBase.extend({
  addAttributes() {
    return {
      ...this.parent?.(),
      marginLeft: {
        default: null,
        parseHTML: (element: HTMLElement) => element.style.marginLeft || null,
        renderHTML: (attrs: Record<string, string>) => {
          if (!attrs.marginLeft) return {};
          return { style: `margin-left: ${attrs.marginLeft}` };
        },
      },
    };
  },

  renderHTML({ HTMLAttributes }) {
    return ['p', mergeAttributes(this.options.HTMLAttributes, HTMLAttributes), 0];
  },

  addCommands() {
    return {
      indent:
        () =>
          ({ commands, editor }) => {
            const current = parseInt(editor.getAttributes('paragraph').marginLeft ?? '0', 10);
            const next = Math.min(current + INDENT_STEP, INDENT_MAX);
            return commands.updateAttributes('paragraph', { marginLeft: next > 0 ? `${next}px` : null });
          },
      outdent:
        () =>
          ({ commands, editor }) => {
            const current = parseInt(editor.getAttributes('paragraph').marginLeft ?? '0', 10);
            const next = Math.max(current - INDENT_STEP, 0);
            return commands.updateAttributes('paragraph', { marginLeft: next > 0 ? `${next}px` : null });
          },
    };
  },
});
