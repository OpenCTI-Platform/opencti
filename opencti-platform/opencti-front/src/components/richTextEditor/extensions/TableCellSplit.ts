import { Extension } from '@tiptap/core';
import { TableMap, selectedRect, CellSelection, cellAround, tableNodeTypes } from '@tiptap/pm/tables';
import type { EditorState, Transaction } from '@tiptap/pm/state';

declare module '@tiptap/core' {
  interface Commands<ReturnType> {
    tableCellSplit: {
      /**
       * Split the current cell horizontally (into two stacked rows).
       * Works on any cell, including 1×1.
       */
      splitCellHorizontal: () => ReturnType;
      /**
       * Split the current cell vertically (into two side-by-side columns).
       * Works on any cell, including 1×1.
       */
      splitCellVertical: () => ReturnType;
    };
  }
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

/** Resolve the cell node + absolute position from the current selection. */
function resolveCell(state: EditorState) {
  const sel = state.selection;
  if (sel instanceof CellSelection) {
    if (sel.$anchorCell.pos !== sel.$headCell.pos) return null;
    return { cellPos: sel.$anchorCell.pos, cellNode: sel.$anchorCell.nodeAfter! };
  }
  const $cell = cellAround(sel.$from);
  if (!$cell) return null;
  return { cellPos: $cell.pos, cellNode: $cell.nodeAfter! };
}

/** Determine the correct cell type (td vs th) for the target cell. */
function getCellNodeType(state: EditorState, node: { type: { spec: Record<string, unknown> } }) {
  const types = tableNodeTypes(state.schema);
  return node.type.spec.tableRole === 'header_cell' ? types.header_cell : types.cell;
}

/** Safely extract the colwidth attribute as a number array, or null. */
function getColwidth(attrs: Record<string, unknown>): number[] | null {
  const cw = attrs.colwidth;
  return Array.isArray(cw) && cw.length > 0 ? (cw as number[]) : null;
}

/**
 * Split a colwidth array in two at `splitAt`.
 * E.g. [100, 200, 150] split at 2 → left=[100,200], right=[150].
 */
function splitColwidthArray(cw: number[] | null, splitAt: number) {
  if (!cw) return { left: null, right: null };
  return { left: cw.slice(0, splitAt), right: cw.slice(splitAt) };
}

/**
 * Halve a single-column colwidth.
 * [200] → first=[100], second=[100].
 * Returns nulls when there's no colwidth to halve.
 */
function halveColwidth(cw: number[] | null) {
  if (!cw || cw.length === 0) return { first: null, second: null };
  const w = cw[0];
  return { first: [Math.ceil(w / 2)], second: [w - Math.ceil(w / 2)] };
}

/**
 * Given a sibling cell's colwidth array and the index (within that array)
 * of the column being split, return a new colwidth with that entry halved
 * into two consecutive entries, keeping the total width unchanged.
 */
function spliceColwidthForSibling(
  cw: number[] | null,
  colIndexInCell: number,
): number[] | null {
  if (!cw || colIndexInCell < 0 || colIndexInCell >= cw.length) return cw;
  const w = cw[colIndexInCell];
  const result = [...cw];
  result.splice(colIndexInCell, 1, Math.ceil(w / 2), w - Math.ceil(w / 2));
  return result;
}

/* ------------------------------------------------------------------ */
/*  Split Horizontal                                                  */
/*  Splits the cell so it occupies two rows.                          */
/*  Strategy:                                                         */
/*    1. Bump rowspan of every OTHER cell in the target row.          */
/*    2. Insert a new <tr> containing only one empty cell (the split  */
/*       target's bottom half) right below the target row.            */
/* ------------------------------------------------------------------ */

function splitCellHorizontalCommand(
  state: EditorState,
  dispatch?: (tr: Transaction) => void,
): boolean {
  const cell = resolveCell(state);
  if (!cell) return false;
  if (!dispatch) return true;

  const { cellNode, cellPos } = cell;
  const cellAttrs = cellNode.attrs as Record<string, unknown>;
  const colspan = (cellAttrs.colspan as number) || 1;
  const rowspan = (cellAttrs.rowspan as number) || 1;

  const rect = selectedRect(state);
  const map = rect.map as TableMap;
  const tableStart = rect.tableStart;
  const table = rect.table;
  const cellRect = map.findCell(cellPos - tableStart);
  const targetRow = cellRect.top;

  const tr = state.tr;
  const types = tableNodeTypes(state.schema);
  const newCellNodeType = getCellNodeType(state, cellNode);

  if (rowspan > 1) {
    // Cell already spans multiple rows — halve the rowspan and insert a
    // new cell into the row where the bottom half starts.
    const topSpan = Math.ceil(rowspan / 2);
    const bottomSpan = rowspan - topSpan;
    tr.setNodeMarkup(cellPos, undefined, { ...cellAttrs, rowspan: topSpan });
    const insertRow = cellRect.top + topSpan;
    const insertPos = map.positionAt(insertRow, cellRect.left, table);
    tr.insert(
      tr.mapping.map(insertPos + tableStart),
      newCellNodeType.createAndFill({ ...cellAttrs, rowspan: bottomSpan, colspan })!,
    );
    dispatch(tr);
    return true;
  }

  // rowspan === 1 — need to insert a whole new <tr>.
  // 1. For every OTHER cell visible in `targetRow`, bump its rowspan.
  const visited = new Set<number>();
  for (let col = 0; col < map.width; col++) {
    if (col >= cellRect.left && col < cellRect.right) continue; // skip target
    const offset = map.map[targetRow * map.width + col];
    if (visited.has(offset)) continue;
    visited.add(offset);
    const pos = tableStart + offset;
    const node = state.doc.nodeAt(pos);
    if (!node) continue;
    const rs = ((node.attrs as Record<string, unknown>).rowspan as number) || 1;
    tr.setNodeMarkup(tr.mapping.map(pos), undefined, { ...node.attrs, rowspan: rs + 1 });
  }

  // 2. Build a new <tr> with a single empty cell for the target column.
  //    Carry over colwidth so column widths don't shift.
  const newCell = newCellNodeType.createAndFill({
    colspan,
    colwidth: cellAttrs.colwidth ?? null,
  })!;
  const newRow = types.row.create(null, [newCell]);

  // Insert the new row right after `targetRow` ends.
  let insertPos = tableStart;
  for (let r = 0; r <= targetRow; r++) {
    insertPos += table.child(r).nodeSize;
  }
  tr.insert(tr.mapping.map(insertPos), newRow);

  dispatch(tr);
  return true;
}

/* ------------------------------------------------------------------ */
/*  Split Vertical                                                    */
/*  Splits the cell so it occupies two columns.                       */
/*  Strategy:                                                         */
/*    1. Bump colspan of every OTHER cell in the target column.       */
/*    2. Insert a new empty cell right after the target cell.         */
/* ------------------------------------------------------------------ */

function splitCellVerticalCommand(
  state: EditorState,
  dispatch?: (tr: Transaction) => void,
): boolean {
  const cell = resolveCell(state);
  if (!cell) return false;
  if (!dispatch) return true;

  const { cellNode, cellPos } = cell;
  const cellAttrs = cellNode.attrs as Record<string, unknown>;
  const colspan = (cellAttrs.colspan as number) || 1;
  const rowspan = (cellAttrs.rowspan as number) || 1;

  const rect = selectedRect(state);
  const map = rect.map as TableMap;
  const tableStart = rect.tableStart;
  const cellRect = map.findCell(cellPos - tableStart);

  const tr = state.tr;
  const newCellNodeType = getCellNodeType(state, cellNode);

  if (colspan > 1) {
    // Cell already spans multiple cols — halve the colspan and insert a
    // new cell right after the current one in the DOM.
    // Split the colwidth array so each half keeps its original column widths.
    const leftSpan = Math.ceil(colspan / 2);
    const rightSpan = colspan - leftSpan;
    const { left: leftCw, right: rightCw } = splitColwidthArray(
      getColwidth(cellAttrs),
      leftSpan,
    );
    tr.setNodeMarkup(cellPos, undefined, {
      ...cellAttrs,
      colspan: leftSpan,
      colwidth: leftCw,
    });
    const insertPos = cellPos + cellNode.nodeSize;
    tr.insert(
      tr.mapping.map(insertPos),
      newCellNodeType.createAndFill({
        ...cellAttrs,
        colspan: rightSpan,
        rowspan,
        colwidth: rightCw,
      })!,
    );
    dispatch(tr);
    return true;
  }

  // colspan === 1 — need to add a column logically.
  // Compute the half-widths of the column being split so sizes are preserved.
  const origCw = getColwidth(cellAttrs);
  const { first: cwFirst, second: cwSecond } = halveColwidth(origCw);

  // 0. Update the target cell's colwidth to the first half.
  if (cwFirst) {
    tr.setNodeMarkup(cellPos, undefined, { ...cellAttrs, colwidth: cwFirst });
  }

  // 1. For every OTHER cell in the target column, bump its colspan
  //    and splice the halved column width into its colwidth array.
  const visited = new Set<number>();
  for (let row = 0; row < map.height; row++) {
    if (row >= cellRect.top && row < cellRect.bottom) continue; // skip target
    const offset = map.map[row * map.width + cellRect.left];
    if (visited.has(offset)) continue;
    visited.add(offset);
    const pos = tableStart + offset;
    const node = state.doc.nodeAt(pos);
    if (!node) continue;
    const nodeAttrs = node.attrs as Record<string, unknown>;
    const cs = (nodeAttrs.colspan as number) || 1;
    // Find the index of the target column within this sibling cell's span.
    const siblingStartCol = map.colCount(offset);
    const colIndexInCell = cellRect.left - siblingStartCol;
    const newCw = spliceColwidthForSibling(getColwidth(nodeAttrs), colIndexInCell);
    tr.setNodeMarkup(tr.mapping.map(pos), undefined, {
      ...nodeAttrs,
      colspan: cs + 1,
      colwidth: newCw,
    });
  }

  // 2. Insert a new empty cell right after the target cell in the DOM.
  const insertPos = cellPos + cellNode.nodeSize;
  tr.insert(
    tr.mapping.map(insertPos),
    newCellNodeType.createAndFill({ rowspan, colwidth: cwSecond })!,
  );

  dispatch(tr);
  return true;
}

/* ------------------------------------------------------------------ */
/*  TipTap Extension                                                  */
/* ------------------------------------------------------------------ */

export const TableCellSplit = Extension.create({
  name: 'tableCellSplit',

  addCommands() {
    return {
      splitCellHorizontal:
        () =>
          ({ state, dispatch }) =>
            splitCellHorizontalCommand(state, dispatch),
      splitCellVertical:
        () =>
          ({ state, dispatch }) =>
            splitCellVerticalCommand(state, dispatch),
    };
  },
});
