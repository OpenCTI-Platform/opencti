import { mergeAttributes } from '@tiptap/core';
import type { Node as ProseMirrorNode } from '@tiptap/pm/model';
import { Table as TiptapTable, TableView, updateColumns, TableOptions } from '@tiptap/extension-table';

/**
 * Custom TableView that re-applies percentage-based column widths stored in
 * node.attrs.colWidths and node.attrs.tableWidth after TipTap's own updateColumns
 * (which is pixel-only) runs.
 */
class CustomTableView extends TableView {
  constructor(node: ProseMirrorNode, cellMinWidth: number) {
    super(node, cellMinWidth);
    this.applyCustomWidths(node);
  }

  update(node: ProseMirrorNode): boolean {
    if (node.type !== this.node.type) return false;
    this.node = node;
    updateColumns(node, this.colgroup, this.table, this.cellMinWidth);
    this.applyCustomWidths(node);
    return true;
  }

  private applyCustomWidths(node: ProseMirrorNode) {
    const colWidths: string[] | null = node.attrs.colWidths;
    const tableWidth: string | null = node.attrs.tableWidth;

    if (colWidths?.length) {
      const cols = Array.from(this.colgroup.children) as HTMLTableColElement[];
      colWidths.forEach((w, i) => {
        if (cols[i] && w) {
          cols[i].style.removeProperty('min-width');
          cols[i].style.width = w;
        }
      });
      this.table.style.tableLayout = 'fixed';
    }

    if (tableWidth) {
      this.table.style.width = tableWidth;
      this.table.style.minWidth = '';
    }
  }
}

/**
 * Extended Table that preserves legacy editor column widths (in %) and table width (in %).
 *
 * Legacy editor stores column widths as <col style="width:X%"> inside a <colgroup>,
 * and wraps the table in <figure class="table" style="width:Y%">.
 * TipTap's built-in Table only handles px-based colwidths stored on cells.
 *
 * This extension adds:
 * - `colWidths`: array of percentage strings parsed from <col style="width:X%">
 * - `tableWidth`: percentage string parsed from <figure class="table" style="width:Y%">
 *   or from <table style="width:Y%">
 *
 * When rendering HTML, if colWidths are present they are re-injected as-is into
 * the colgroup, bypassing TipTap's px-based createColGroup utility.
 */
export const Table = TiptapTable.extend({
  addOptions(): TableOptions {
    const parentOptions = (this.parent?.() || {}) as TableOptions;
    return {
      ...parentOptions,
      HTMLAttributes: parentOptions.HTMLAttributes || {},
      View: CustomTableView,
    } as TableOptions;
  },

  addAttributes() {
    return {
      ...this.parent?.(),
      colWidths: {
        default: null,
        parseHTML: (element: HTMLElement) => {
          const cols = element.querySelectorAll(':scope > colgroup > col');
          if (!cols.length) return null;
          const widths = Array.from(cols).map(
            (col) => (col as HTMLElement).style.width || (col as HTMLElement).getAttribute('width') || '',
          );
          // Only store if at least one column has a meaningful width
          return widths.some((w) => w) ? widths : null;
        },
        renderHTML: () => ({}), // handled manually in renderHTML
      },
      tableWidth: {
        default: null,
        parseHTML: (element: HTMLElement) => {
          // Try inline style on the <table> itself first
          if (element.style.width && !element.style.width.startsWith('min-')) {
            return element.style.width;
          }
          // Fall back to the wrapping <figure class="table"> if present
          const figure = element.closest('figure.table') as HTMLElement | null;
          if (figure?.style.width) return figure.style.width;
          return null;
        },
        renderHTML: () => ({}), // handled manually in renderHTML
      },
    };
  },

  renderHTML({ node, HTMLAttributes }: { node: ProseMirrorNode; HTMLAttributes: Record<string, unknown> }) {
    const colWidths: string[] | null = node.attrs.colWidths;
    const tableWidth: string | null = node.attrs.tableWidth;

    // Build colgroup: prefer stored % widths, otherwise fall back to TipTap default
    let colgroup;
    if (colWidths?.length) {
      colgroup = [
        'colgroup',
        {},
        ...colWidths.map((w) => ['col', { style: w ? `width: ${w}` : '' }]),
      ];
    } else {
      // Re-use TipTap's createColGroup via parent renderHTML — but we need the colgroup only.
      // Easiest: call parent and extract its colgroup by letting it run, then override style.
      // Since we can't easily extract it, we build a simple fallback.
      const cellMinWidth = this.options.cellMinWidth ?? 25;
      const row = node.firstChild;
      const cols = [];
      if (row) {
        for (let i = 0; i < row.childCount; i += 1) {
          const cell = row.child(i);
          const { colspan, colwidth } = cell.attrs;
          for (let j = 0; j < colspan; j += 1) {
            const w = colwidth?.[j];
            cols.push(['col', { style: w ? `width: ${w}px` : `min-width: ${cellMinWidth}px` }]);
          }
        }
      }
      colgroup = ['colgroup', {}, ...cols];
    }

    const styleAttr = tableWidth
      ? `width: ${tableWidth}; table-layout: fixed`
      : colWidths?.length ? 'table-layout: fixed' : undefined;

    const tableNode = [
      'table',
      mergeAttributes(this.options.HTMLAttributes, HTMLAttributes, styleAttr ? { style: styleAttr } : {}),
      colgroup,
      ['tbody', 0],
    ];

    // the legacy editor wraps tables in <figure class="table">
    return [
      'figure',
      { class: 'table' },
      tableNode,
    ];
  },
});
