import { Node, mergeAttributes, canInsertNode, isNodeSelection, nodeInputRule } from '@tiptap/core';
import { TextSelection, NodeSelection } from '@tiptap/pm/state';

declare module '@tiptap/core' {
  interface Commands<ReturnType> {
    pageBreak: {
      setPageBreak: () => ReturnType;
    };
  }
}

/**
 * Page break extension for PDF export compatibility.
 * Renders <div class="page-break"></div> for pdfPageBreaks utility.
 */
export const PageBreak = Node.create({
  name: 'pageBreak',

  addOptions() {
    return {
      HTMLAttributes: {
        class: 'page-break',
      },
    };
  },

  group: 'block',

  parseHTML() {
    return [
      { tag: 'div.page-break' },
    ];
  },

  renderHTML({ HTMLAttributes }) {
    return ['div', mergeAttributes(this.options.HTMLAttributes, HTMLAttributes)];
  },

  addCommands() {
    return {
      setPageBreak:
        () =>
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
          ({ chain, state }: { chain: any; state: any }) => {
            if (!canInsertNode(state, state.schema.nodes[this.name])) {
              return false;
            }
            const { selection } = state;
            const { $from: $originFrom, $to: $originTo } = selection;
            const currentChain = chain();

            if ($originFrom.parentOffset === 0) {
              currentChain.insertContentAt(
                { from: Math.max($originFrom.pos - 1, 0), to: $originTo.pos },
                { type: this.name },
              );
            } else if (isNodeSelection(selection)) {
              currentChain.insertContentAt($originTo.pos, { type: this.name });
            } else {
              currentChain.insertContent({ type: this.name });
            }

            return currentChain
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
              .command(({ tr, dispatch }: { tr: any; dispatch?: any }) => {
                if (dispatch) {
                  const { $to } = tr.selection;
                  const nodeAfter = $to.nodeAfter;
                  if (nodeAfter?.isTextblock) {
                    tr.setSelection(TextSelection.create(tr.doc, $to.pos + 1));
                  } else if (nodeAfter?.isBlock) {
                    tr.setSelection(NodeSelection.create(tr.doc, $to.pos));
                  } else {
                    tr.setSelection(TextSelection.create(tr.doc, $to.pos));
                  }
                  tr.scrollIntoView();
                }
                return true;
              })
              .run();
          },
    };
  },

  addInputRules() {
    return [
      nodeInputRule({
        find: /^\/pagebreak$/,
        type: this.type,
      }),
    ];
  },
});
