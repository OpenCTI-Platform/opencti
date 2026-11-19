import React, { forwardRef, useImperativeHandle, useRef, useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, render } from '@testing-library/react';
import ReactFlow, { addEdge, type Connection, type Edge, type Node, useReactFlow } from 'reactflow';
import usePlaybookRewiring from './usePlaybookRewiring';
import {
  canUndo,
  canvasSnapshot,
  emptyHistory,
  type PlaybookHistory,
  type PlaybookOperation,
  type PlaybookOperationResult,
  type PlaybookSnapshot,
  recordOperation,
} from '../utils/playbookHistory';

const commitMutation = vi.fn();
vi.mock('../../../../../relay/environment', () => ({
  commitMutation: (config: unknown) => commitMutation(config),
  MESSAGING$: { notifyError: vi.fn() },
}));
vi.mock('../../../../../components/i18n', () => ({ useFormatter: () => ({ t_i18n: (key: string) => key }) }));

const component = (id: string, outs: string[], is_entry_point = false) => ({
  id,
  is_entry_point,
  ports: outs.map((p) => ({ id: p, type: 'out' })),
});
const LISTEN = component('LISTEN', ['out'], true);
const MATCH = component('MATCH', ['out', 'no-match']);
const LOG = component('LOG', ['out']);
const outPortsOf = (componentId: string) => [LISTEN, MATCH, LOG].find((c) => c.id === componentId)?.ports.map((p) => p.id) ?? [];

const step = (id: string, c: ReturnType<typeof component>): Node => ({ id, type: 'workflow', position: { x: 0, y: 0 }, data: { name: id, component: c } });
const link = (id: string, source: string, sourceHandle: string, target: string): Edge => ({ id, type: 'workflow', source, sourceHandle, target });

// entry -> a(MATCH); a.out -> b; a.no-match -> c
const NODES = [step('entry', LISTEN), step('a', MATCH), step('b', LOG), step('c', LOG)];
const EDGES = [link('l1', 'entry', 'out', 'a'), link('l2', 'a', 'out', 'b'), link('l3', 'a', 'no-match', 'c')];

interface Probe {
  // What React Flow does when a connection is drawn on the canvas: the connection is added to its
  // edges (defaultEdges), then onConnect is called.
  draw: (connection: Connection) => void;
  update: (oldEdge: Edge, connection: Connection) => void;
  history: () => PlaybookHistory;
  edges: () => Edge[];
}

const Rewiring = forwardRef<Probe, { canEdit?: boolean }>(({ canEdit = true }, ref) => {
  const { getNodes, getEdges, setEdges } = useReactFlow();
  const historyRef = useRef<PlaybookHistory>(emptyHistory());
  // The recorder the editor gives the hook: the real canvas snapshot and the real history.
  const [recorder] = useState(() => ({
    snapshot: () => canvasSnapshot(getNodes(), getEdges()),
    record: (op: PlaybookOperation, before: PlaybookSnapshot, result?: PlaybookOperationResult) => {
      historyRef.current = recordOperation(historyRef.current, op, before, outPortsOf, result);
    },
  }));
  const { onConnect, onEdgeUpdate } = usePlaybookRewiring('playbook', vi.fn(), vi.fn(), vi.fn(), recorder, canEdit);
  useImperativeHandle(ref, () => ({
    draw: (connection: Connection) => {
      setEdges(addEdge(connection, getEdges()));
      onConnect(connection);
    },
    update: (oldEdge: Edge, connection: Connection) => onEdgeUpdate(oldEdge, connection),
    history: () => historyRef.current,
    edges: () => getEdges(),
  }));
  return null;
});
Rewiring.displayName = 'Rewiring';

const canvas = (probe: React.RefObject<Probe | null>, canEdit: boolean) => (
  <div style={{ width: 800, height: 600 }}>
    <ReactFlow defaultNodes={NODES} defaultEdges={EDGES}>
      <Rewiring ref={probe} canEdit={canEdit} />
    </ReactFlow>
  </div>
);

const renderCanvas = (canEdit = true) => {
  const probe = React.createRef<Probe>();
  const { rerender } = render(canvas(probe, canEdit));
  return {
    get current() {
      return probe.current;
    },
    switchMode: (next: boolean) => rerender(canvas(probe, next)),
  };
};

// The server accepts the move and answers the id of the new link.
const serverMoves = (newLinkId: string) => {
  commitMutation.mockImplementation((config: { onCompleted: (response: unknown) => void }) => {
    config.onCompleted({ playbookMoveNode: newLinkId });
  });
};

describe('a step moved by drawing a connection', () => {
  afterEach(() => commitMutation.mockReset());

  it('records one history entry that moves the step back under its previous port', () => {
    serverMoves('l9');
    const probe = renderCanvas();
    act(() => probe.current?.draw({ source: 'b', sourceHandle: 'out', target: 'c', targetHandle: null }));
    expect(commitMutation).toHaveBeenCalledTimes(1);
    const history = probe.current!.history();
    expect(canUndo(history)).toBe(true);
    expect(history.past).toHaveLength(1);
    expect(history.past[0].undo).toEqual({ kind: 'move', nodeId: 'c', parentNodeId: 'a', parentPortId: 'no-match' });
    // The canvas shows the link the server answered, never the edge React Flow drew.
    const ids = probe.current!.edges().filter((e) => e.type !== 'placeholder').map((e) => e.id).sort();
    expect(ids).toEqual(['l1', 'l2', 'l9']);
  });

  it('keeps the entries recorded before it', () => {
    serverMoves('l9');
    const probe = renderCanvas();
    act(() => probe.current?.draw({ source: 'b', sourceHandle: 'out', target: 'c', targetHandle: null }));
    serverMoves('l10');
    act(() => probe.current?.draw({ source: 'a', sourceHandle: 'out', target: 'c', targetHandle: null }));
    const history = probe.current!.history();
    expect(history.past).toHaveLength(2);
    expect(history.past[1].undo).toEqual({ kind: 'move', nodeId: 'c', parentNodeId: 'b', parentPortId: 'out' });
  });

  it('leaves nothing drawn when the connection is refused', () => {
    const probe = renderCanvas();
    // b under its own child would be a loop: nothing is sent, the drawn edge goes away.
    act(() => probe.current?.draw({ source: 'b', sourceHandle: 'out', target: 'a', targetHandle: null }));
    expect(commitMutation).not.toHaveBeenCalled();
    expect(probe.current!.edges().some((e) => e.id.startsWith('reactflow__edge-'))).toBe(false);
  });
});

describe('view mode', () => {
  afterEach(() => commitMutation.mockReset());

  it('saves nothing when a connection is drawn after switching from edit to view mode', () => {
    serverMoves('l9');
    const probe = renderCanvas(true);
    act(() => probe.switchMode(false));
    act(() => probe.current?.draw({ source: 'b', sourceHandle: 'out', target: 'c', targetHandle: null }));
    act(() => probe.current?.update(EDGES[2], { source: 'a', sourceHandle: 'no-match', target: 'b', targetHandle: null }));
    expect(commitMutation).not.toHaveBeenCalled();
    expect(probe.current!.history().past).toHaveLength(0);
    const ids = probe.current!.edges().filter((e) => e.type !== 'placeholder').map((e) => e.id).sort();
    expect(ids).toEqual(['l1', 'l2', 'l3']);
  });

  it('saves nothing when view mode is the landing mode, and saves again back in edit mode', () => {
    serverMoves('l9');
    const probe = renderCanvas(false);
    act(() => probe.current?.draw({ source: 'b', sourceHandle: 'out', target: 'c', targetHandle: null }));
    expect(commitMutation).not.toHaveBeenCalled();
    act(() => probe.switchMode(true));
    act(() => probe.current?.draw({ source: 'b', sourceHandle: 'out', target: 'c', targetHandle: null }));
    expect(commitMutation).toHaveBeenCalledTimes(1);
  });
});
