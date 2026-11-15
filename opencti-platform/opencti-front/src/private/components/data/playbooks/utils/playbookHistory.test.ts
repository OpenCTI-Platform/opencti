import { describe, expect, it } from 'vitest';
import {
  afterRedo,
  afterUndo,
  canRedo,
  canUndo,
  emptyHistory,
  inverseOf,
  PLAYBOOK_HISTORY_LIMIT,
  type PlaybookOperation,
  type PlaybookSnapshot,
  recordOperation,
} from './playbookHistory';

const position = { x: 0, y: 0 };
const step = (id: string, component_id: string) => ({ id, component_id, name: id, configuration: '{}', position });
const link = (id: string, from: string, port: string, to: string) => ({ id, from: { id: from, port }, to: { id: to } });

// entry -out-> a -out-> b ; a -no-match-> c
const snapshot: PlaybookSnapshot = {
  nodes: [step('entry', 'LISTEN'), step('a', 'FILTER'), step('b', 'LOG'), step('c', 'LOG')],
  links: [link('l1', 'entry', 'out', 'a'), link('l2', 'a', 'out', 'b'), link('l3', 'a', 'no-match', 'c')],
};
const ports: Record<string, string[]> = { LISTEN: ['out'], FILTER: ['out', 'no-match'], LOG: ['out'], END: [] };
const outPortsOf = (componentId: string) => ports[componentId] ?? [];

describe('inverseOf', () => {
  it('deletes an added step', () => {
    const op: PlaybookOperation = { kind: 'add', nodeId: 'd', node: { ...step('d', 'LOG') }, parentNodeId: 'b', parentPortId: 'out' };
    expect(inverseOf(op, snapshot, outPortsOf)).toEqual({ kind: 'delete', nodeId: 'd' });
  });

  it('re-adds a deleted leaf under its parent port', () => {
    expect(inverseOf({ kind: 'delete', nodeId: 'c' }, snapshot, outPortsOf)).toEqual({
      kind: 'add',
      nodeId: 'c',
      node: { component_id: 'LOG', name: 'c', configuration: '{}', position },
      parentNodeId: 'a',
      parentPortId: 'no-match',
    });
  });

  it('has no inverse for a step deleted with its branch', () => {
    expect(inverseOf({ kind: 'delete', nodeId: 'a' }, snapshot, outPortsOf)).toBeNull();
  });

  it('restores the previous component of a replaced step', () => {
    const op: PlaybookOperation = { kind: 'replace', nodeId: 'b', node: { component_id: 'FILTER', name: 'x', configuration: null, position } };
    expect(inverseOf(op, snapshot, outPortsOf)).toEqual({
      kind: 'replace',
      nodeId: 'b',
      node: { component_id: 'LOG', name: 'b', configuration: '{}', position },
    });
  });

  it('has no inverse for a replacement that drops a branch', () => {
    const op: PlaybookOperation = { kind: 'replace', nodeId: 'a', node: { component_id: 'LOG', name: 'a', configuration: null, position } };
    expect(inverseOf(op, snapshot, outPortsOf)).toBeNull();
  });

  it('points a relinked link back to where it was', () => {
    const op: PlaybookOperation = { kind: 'relink', linkId: 'l2', toNodeId: 'c', fromNodeId: 'a', fromPortId: 'out' };
    expect(inverseOf(op, snapshot, outPortsOf)).toEqual({ kind: 'relink', linkId: 'l2', toNodeId: 'b', fromNodeId: 'a', fromPortId: 'out' });
  });

  it('moves a moved step back under its previous parent port', () => {
    const op: PlaybookOperation = { kind: 'move', nodeId: 'c', parentNodeId: 'b', parentPortId: 'out' };
    expect(inverseOf(op, snapshot, outPortsOf)).toEqual({ kind: 'move', nodeId: 'c', parentNodeId: 'a', parentPortId: 'no-match' });
  });
});

describe('history', () => {
  it('records, undoes and redoes, and a new change clears the redo', () => {
    let history = recordOperation(emptyHistory(), { kind: 'relink', linkId: 'l2', toNodeId: 'c', fromNodeId: 'a', fromPortId: 'out' }, snapshot, outPortsOf);
    expect(canUndo(history)).toBe(true);
    expect(canRedo(history)).toBe(false);
    history = afterUndo(history, {}, snapshot);
    expect(canUndo(history)).toBe(false);
    expect(canRedo(history)).toBe(true);
    history = afterRedo(history, {}, snapshot);
    expect(history.past).toHaveLength(1);
    history = afterUndo(history, {}, snapshot);
    history = recordOperation(history, { kind: 'move', nodeId: 'c', parentNodeId: 'b', parentPortId: 'out' }, snapshot, outPortsOf, { linkId: 'l9' });
    expect(canRedo(history)).toBe(false);
  });

  it('ends the history on a change without inverse', () => {
    const history = recordOperation(emptyHistory(), { kind: 'relink', linkId: 'l2', toNodeId: 'c', fromNodeId: 'a', fromPortId: 'out' }, snapshot, outPortsOf);
    expect(recordOperation(history, { kind: 'delete', nodeId: 'a' }, snapshot, outPortsOf)).toEqual(emptyHistory());
  });

  it('follows the new id of a step re-created by an undo', () => {
    // relink l2 to c, then delete leaf b: undoing the delete re-creates b as b2.
    const afterDelete: PlaybookSnapshot = {
      nodes: snapshot.nodes,
      links: [link('l1', 'entry', 'out', 'a'), link('l2', 'a', 'out', 'c'), link('l3', 'a', 'no-match', 'b')],
    };
    let history = recordOperation(emptyHistory(), { kind: 'relink', linkId: 'l2', toNodeId: 'c', fromNodeId: 'a', fromPortId: 'out' }, snapshot, outPortsOf);
    history = recordOperation(history, { kind: 'delete', nodeId: 'b' }, afterDelete, outPortsOf);
    history = afterUndo(history, { nodeId: 'b2' }, afterDelete);
    expect(history.future[0].do).toEqual({ kind: 'delete', nodeId: 'b2' });
    history = afterUndo(history, {}, afterDelete);
    expect(history.future[0].do).toMatchObject({ kind: 'relink', linkId: 'l2' });
  });

  it('follows the new link a move creates', () => {
    // move c under b: l3 is replaced by l9; a later relink of l9 must be undone on l9.
    const moved: PlaybookSnapshot = { nodes: snapshot.nodes, links: [link('l1', 'entry', 'out', 'a'), link('l2', 'a', 'out', 'b'), link('l9', 'b', 'out', 'c')] };
    let history = recordOperation(emptyHistory(), { kind: 'move', nodeId: 'c', parentNodeId: 'b', parentPortId: 'out' }, snapshot, outPortsOf, { linkId: 'l9' });
    history = recordOperation(history, { kind: 'relink', linkId: 'l9', toNodeId: 'c', fromNodeId: 'a', fromPortId: 'no-match' }, moved, outPortsOf);
    expect(history.past[1].undo).toEqual({ kind: 'relink', linkId: 'l9', toNodeId: 'c', fromNodeId: 'b', fromPortId: 'out' });
    // undoing the relink then the move: the move back replaces l9 by l10, the redo of the relink names l10.
    history = afterUndo(history, {}, moved);
    history = afterUndo(history, { linkId: 'l10' }, moved);
    expect(history.future[1].do).toMatchObject({ kind: 'relink', linkId: 'l10' });
  });

  it('keeps the newest entries only', () => {
    let history = emptyHistory();
    for (let i = 0; i < PLAYBOOK_HISTORY_LIMIT + 5; i += 1) {
      history = recordOperation(history, { kind: 'relink', linkId: 'l2', toNodeId: 'c', fromNodeId: 'a', fromPortId: 'out' }, snapshot, outPortsOf);
    }
    expect(history.past).toHaveLength(PLAYBOOK_HISTORY_LIMIT);
  });
});
