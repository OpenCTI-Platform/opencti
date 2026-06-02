import { renderHook, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Node, Edge, Position } from 'reactflow';
import useAutoLayout from './useWorkflowLayout';
import { WorkflowNodeType } from '../utils';

// ---------------------------------------------------------------------------
// Hoisted mocks — must be created before vi.mock factory runs
// ---------------------------------------------------------------------------
const hoisted = vi.hoisted(() => ({
  mockSetNodes: vi.fn(),
  mockSetEdges: vi.fn(),
  nodesInitialized: true as boolean,
  nodeMap: new Map<string, Node>(),
  edges: [] as Edge[],
  // Tracks the previous selector result so the useStore mock can invoke the
  // compareElements equality function on subsequent renders, exercising the
  // compareElements / compareNodes / compareEdges code paths.
  prevElements: null as unknown,
}));

vi.mock('reactflow', async () => {
  const actual = await vi.importActual('reactflow');
  return {
    ...actual,
    useReactFlow: () => ({
      setNodes: hoisted.mockSetNodes,
      setEdges: hoisted.mockSetEdges,
    }),
    useNodesInitialized: () => hoisted.nodesInitialized,
    // Call the selector with the mocked store state AND invoke the comparison function
    // on rerenders so that compareElements / compareNodes / compareEdges are exercised.
    useStore: (
      selector: (state: { nodeInternals: Map<string, Node>; edges: Edge[] }) => unknown,
      compare?: (prev: unknown, next: unknown) => boolean,
    ) => {
      const next = selector({ nodeInternals: hoisted.nodeMap, edges: hoisted.edges });
      if (hoisted.prevElements !== null && compare) {
        compare(hoisted.prevElements, next);
      }
      hoisted.prevElements = next;
      return next;
    },
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const makeStatusNode = (id: string, width = 100, height = 50): Node => ({
  id,
  type: WorkflowNodeType.status,
  position: { x: 0, y: 0 },
  data: {},
  width,
  height,
});

const makeTransitionNode = (id: string, width = 30, height = 30): Node => ({
  id,
  type: WorkflowNodeType.transition,
  position: { x: 0, y: 0 },
  data: {},
  width,
  height,
});

const makeEdge = (id: string, source: string, target: string): Edge => ({ id, source, target });

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('useWorkflowLayout', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.nodesInitialized = true;
    hoisted.nodeMap = new Map();
    hoisted.edges = [];
    hoisted.prevElements = null;
  });

  // -------------------------------------------------------------------------
  // No-op conditions
  // -------------------------------------------------------------------------
  describe('no-op conditions', () => {
    it('should not call setNodes when nodes are not initialized', async () => {
      hoisted.nodesInitialized = false;
      hoisted.nodeMap = new Map([['s1', makeStatusNode('s1')]]);

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      // Give the async runLayout a chance to run (it shouldn't)
      await Promise.resolve();
      expect(hoisted.mockSetNodes).not.toHaveBeenCalled();
    });

    it('should not call setNodes when the node map is empty', async () => {
      hoisted.nodesInitialized = true;
      hoisted.nodeMap = new Map();

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await Promise.resolve();
      expect(hoisted.mockSetNodes).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // Basic layout execution
  // -------------------------------------------------------------------------
  describe('layout execution', () => {
    it('should call setNodes and setEdges once nodes are present and initialized', async () => {
      hoisted.nodeMap = new Map([['s1', makeStatusNode('s1')]]);

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await waitFor(() => {
        expect(hoisted.mockSetNodes).toHaveBeenCalled();
        expect(hoisted.mockSetEdges).toHaveBeenCalled();
      });
    });

    it('should set style.opacity to 1 on every node', async () => {
      const t1 = makeTransitionNode('t1');
      const s1 = makeStatusNode('s1');
      hoisted.nodeMap = new Map([['s1', s1], ['t1', t1]]);
      hoisted.edges = [makeEdge('e1', 's1', 't1')];

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      const resultNodes: Node[] = hoisted.mockSetNodes.mock.calls[0][0];
      resultNodes.forEach((node) => expect(node.style?.opacity).toBe(1));
    });

    it('should set style.opacity to 1 on every edge', async () => {
      // Two nodes with a valid directed edge — a self-loop would break d3-hierarchy's stratify
      const s1 = makeStatusNode('s1');
      const s2 = makeStatusNode('s2');
      hoisted.nodeMap = new Map([['s1', s1], ['s2', s2]]);
      hoisted.edges = [makeEdge('e1', 's1', 's2')];

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await waitFor(() => expect(hoisted.mockSetEdges).toHaveBeenCalled());
      const resultEdges: Edge[] = hoisted.mockSetEdges.mock.calls[0][0];
      expect(resultEdges.length).toBeGreaterThan(0);
      resultEdges.forEach((e) => expect(e.style?.opacity).toBe(1));
    });

    it('should assign a numeric x/y position to every node in a linear chain', async () => {
      const s1 = makeStatusNode('s1');
      const t1 = makeTransitionNode('t1');
      // s2 has no explicit dimensions — exercises the `node.height ?? 0` fallback
      // in the forward-node offset calculation (L202 else branch)
      const s2: Node = { id: 's2', type: WorkflowNodeType.status, position: { x: 0, y: 0 }, data: {} };
      hoisted.nodeMap = new Map([['s1', s1], ['t1', t1], ['s2', s2]]);
      hoisted.edges = [makeEdge('e1', 's1', 't1'), makeEdge('e2', 't1', 's2')];

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      const resultNodes: Node[] = hoisted.mockSetNodes.mock.calls[0][0];

      expect(resultNodes).toHaveLength(3);
      resultNodes.forEach((node) => {
        expect(typeof node.position.x).toBe('number');
        expect(typeof node.position.y).toBe('number');
      });
    });
  });

  // -------------------------------------------------------------------------
  // Handle positions per direction
  // -------------------------------------------------------------------------
  describe('handle positions by direction', () => {
    const runAndGetNodes = async (direction: 'TB' | 'LR' | 'BT' | 'RL') => {
      hoisted.nodeMap = new Map([['s1', makeStatusNode('s1')]]);
      hoisted.edges = [];
      renderHook(() => useAutoLayout({ direction, spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      return hoisted.mockSetNodes.mock.calls[0][0] as Node[];
    };

    it('TB: sourcePosition=Bottom, targetPosition=Top', async () => {
      const nodes = await runAndGetNodes('TB');
      nodes.forEach((n) => {
        expect(n.sourcePosition).toBe(Position.Bottom);
        expect(n.targetPosition).toBe(Position.Top);
      });
    });

    it('BT: sourcePosition=Top, targetPosition=Bottom', async () => {
      const nodes = await runAndGetNodes('BT');
      nodes.forEach((n) => {
        expect(n.sourcePosition).toBe(Position.Top);
        expect(n.targetPosition).toBe(Position.Bottom);
      });
    });

    it('LR: sourcePosition=Right, targetPosition=Left', async () => {
      const nodes = await runAndGetNodes('LR');
      nodes.forEach((n) => {
        expect(n.sourcePosition).toBe(Position.Right);
        expect(n.targetPosition).toBe(Position.Left);
      });
    });

    it('RL: sourcePosition=Left, targetPosition=Right', async () => {
      const nodes = await runAndGetNodes('RL');
      nodes.forEach((n) => {
        expect(n.sourcePosition).toBe(Position.Left);
        expect(n.targetPosition).toBe(Position.Right);
      });
    });
  });

  // -------------------------------------------------------------------------
  // Backward-transition detection
  //
  // Setup: s1 → t1 → s2 → t2 → s3, plus t_back: s3 → t_back → s2.
  //
  // In the first-pass d3 hierarchy, s2's first incomer is t1 (edge order),
  // so the hierarchy is a valid DAG: rootNode → s1 → t1 → s2 → t2 → s3 → t_back.
  // s2 IS an ancestor of s3, so t_back is correctly detected as backward.
  // In the second pass (forward nodes only), t_back is excluded and placed at
  // the midpoint of s3 and s2 with a horizontal offset.
  // -------------------------------------------------------------------------
  describe('backward transition detection', () => {
    it('should include the backward transition node in the output with opacity 1', async () => {
      const s1 = makeStatusNode('s1');
      const t1 = makeTransitionNode('t1');
      const s2 = makeStatusNode('s2');
      const t2 = makeTransitionNode('t2');
      const s3 = makeStatusNode('s3');
      const t_back = makeTransitionNode('t_back');

      hoisted.nodeMap = new Map([
        ['s1', s1], ['t1', t1], ['s2', s2],
        ['t2', t2], ['s3', s3], ['t_back', t_back],
      ]);
      // e1-e4: forward chain; e5-e6: backward (t_back loops s3 → t_back → s2)
      hoisted.edges = [
        makeEdge('e1', 's1', 't1'),
        makeEdge('e2', 't1', 's2'),
        makeEdge('e3', 's2', 't2'),
        makeEdge('e4', 't2', 's3'),
        makeEdge('e5', 's3', 't_back'),
        makeEdge('e6', 't_back', 's2'), // s2 is an ancestor of s3 → backward
      ];

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      const resultNodes: Node[] = hoisted.mockSetNodes.mock.calls[0][0];

      // All 6 nodes must be present
      expect(resultNodes).toHaveLength(6);

      const tBackResult = resultNodes.find((n) => n.id === 't_back');
      expect(tBackResult).toBeDefined();
      expect(tBackResult?.style?.opacity).toBe(1);
      // Backward-transition nodes are placed via the midpoint formula,
      // producing a valid numeric position
      expect(typeof tBackResult?.position.x).toBe('number');
      expect(typeof tBackResult?.position.y).toBe('number');
    });

    it('should not mark a forward transition as backward', async () => {
      // Simple s1 → t1 → s2: t1 target (s2) is NOT an ancestor of s1, so t1 is forward
      const s1 = makeStatusNode('s1');
      const t1 = makeTransitionNode('t1');
      const s2 = makeStatusNode('s2');

      hoisted.nodeMap = new Map([['s1', s1], ['t1', t1], ['s2', s2]]);
      hoisted.edges = [makeEdge('e1', 's1', 't1'), makeEdge('e2', 't1', 's2')];

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      const resultNodes: Node[] = hoisted.mockSetNodes.mock.calls[0][0];

      // t1 must receive a position from the d3 layout (not the midpoint fallback)
      const t1Result = resultNodes.find((n) => n.id === 't1');
      expect(t1Result?.position).toBeDefined();
      expect(typeof t1Result?.position.x).toBe('number');
    });
    it('should use 0 as offset when backward transition node has no dimensions', async () => {
      // Same topology as the basic backward-transition test, but t_back has no
      // width/height so the `node.width ?? 0` and `node.height ?? 0` branches
      // (L177, L178, L202) in the midpoint offset calculation are exercised.
      const s1 = makeStatusNode('s1');
      const t1 = makeTransitionNode('t1');
      const s2 = makeStatusNode('s2');
      const t2 = makeTransitionNode('t2');
      const s3 = makeStatusNode('s3');
      const t_back: Node = { id: 't_back', type: WorkflowNodeType.transition, position: { x: 0, y: 0 }, data: {} };

      hoisted.nodeMap = new Map([
        ['s1', s1], ['t1', t1], ['s2', s2], ['t2', t2], ['s3', s3], ['t_back', t_back],
      ]);
      hoisted.edges = [
        makeEdge('e1', 's1', 't1'),
        makeEdge('e2', 't1', 's2'),
        makeEdge('e3', 's2', 't2'),
        makeEdge('e4', 't2', 's3'),
        makeEdge('e5', 's3', 't_back'),
        makeEdge('e6', 't_back', 's2'),
      ];

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      const resultNodes: Node[] = hoisted.mockSetNodes.mock.calls[0][0];
      const tBackResult = resultNodes.find((n) => n.id === 't_back');
      expect(tBackResult?.style?.opacity).toBe(1);
      expect(typeof tBackResult?.position.x).toBe('number');
    });
  });

  // -------------------------------------------------------------------------
  describe('multiple disconnected status nodes', () => {
    it('should position all nodes when there are no connecting edges', async () => {
      const s1 = makeStatusNode('s1');
      const s2 = makeStatusNode('s2');
      hoisted.nodeMap = new Map([['s1', s1], ['s2', s2]]);
      hoisted.edges = [];

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      const resultNodes: Node[] = hoisted.mockSetNodes.mock.calls[0][0];

      expect(resultNodes).toHaveLength(2);
      resultNodes.forEach((n) => {
        expect(typeof n.position.x).toBe('number');
        expect(typeof n.position.y).toBe('number');
      });
    });
  });

  // -------------------------------------------------------------------------
  // Nodes without explicit dimensions — exercises the `node.width ?? 0` and
  // `node.height ?? 0` fallbacks in layoutAlgorithm (L67, L68).
  // -------------------------------------------------------------------------
  describe('nodes without explicit dimensions', () => {
    it('should use 0 as fallback width/height when node dimensions are undefined', async () => {
      const noDim: Node = {
        id: 's1',
        type: WorkflowNodeType.status,
        position: { x: 0, y: 0 },
        data: {},
        // width and height intentionally omitted
      };
      hoisted.nodeMap = new Map([['s1', noDim]]);

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      const resultNodes: Node[] = hoisted.mockSetNodes.mock.calls[0][0];
      expect(resultNodes[0].style?.opacity).toBe(1);
      expect(typeof resultNodes[0].position.x).toBe('number');
    });
  });

  // -------------------------------------------------------------------------
  // Parallel-branch backward transition — exercises the isLeftBranch path.
  //
  // Tree: s1 has two children (t1_l → s2_l → t2_l → s3_l  and  t1_r → s2_r).
  // t_back connects s3_l → t_back → s2_l (backward: s2_l is an ancestor of s3_l).
  // d3 places the longer subtree (left branch) to the left of root.x so
  // isLeftBranch = true, giving t_back a negative horizontal offset.
  // -------------------------------------------------------------------------
  describe('backward transition in parallel-branch tree', () => {
    it('should position backward transition correctly when source is on the left branch', async () => {
      const s1 = makeStatusNode('s1');
      const t1_l = makeTransitionNode('t1_l');
      const s2_l = makeStatusNode('s2_l');
      const t2_l = makeTransitionNode('t2_l');
      const s3_l = makeStatusNode('s3_l');
      const t1_r = makeTransitionNode('t1_r');
      const s2_r = makeStatusNode('s2_r');
      const t_back = makeTransitionNode('t_back');

      // Insert left-branch nodes first so they appear before right-branch in the
      // stratify input — d3 places the first sibling to the left of center.
      hoisted.nodeMap = new Map([
        ['s1', s1], ['t1_l', t1_l], ['s2_l', s2_l], ['t2_l', t2_l], ['s3_l', s3_l],
        ['t1_r', t1_r], ['s2_r', s2_r], ['t_back', t_back],
      ]);
      hoisted.edges = [
        makeEdge('e1', 's1', 't1_l'),
        makeEdge('e2', 't1_l', 's2_l'),
        makeEdge('e3', 's2_l', 't2_l'),
        makeEdge('e4', 't2_l', 's3_l'),
        makeEdge('e5', 's1', 't1_r'),
        makeEdge('e6', 't1_r', 's2_r'),
        makeEdge('e7', 's3_l', 't_back'),
        // e2 (t1_l→s2_l) comes before e8 (t_back→s2_l) → s2_l's parent = t1_l (no cycle)
        makeEdge('e8', 't_back', 's2_l'),
      ];

      renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));

      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      const resultNodes: Node[] = hoisted.mockSetNodes.mock.calls[0][0];

      expect(resultNodes).toHaveLength(8);
      const tBackResult = resultNodes.find((n) => n.id === 't_back');
      expect(tBackResult?.style?.opacity).toBe(1);
      expect(typeof tBackResult?.position.x).toBe('number');
      expect(typeof tBackResult?.position.y).toBe('number');
    });
  });

  // -------------------------------------------------------------------------
  // compareElements / compareNodes / compareEdges
  //
  // These are private module-level functions passed as the equality argument
  // to useStore. The mock above records the previous selector result and invokes
  // compare(prev, next) on every subsequent render, exercising all branches.
  // -------------------------------------------------------------------------
  describe('compareElements (invoked via useStore on rerender)', () => {
    const makeN = (id: string, extra?: Partial<Node>): Node => ({
      id, type: WorkflowNodeType.status, position: { x: 0, y: 0 }, data: {},
      width: 100, height: 50, ...extra,
    });
    const makeE = (id: string, source: string, target: string, opts?: Partial<Edge>): Edge => ({
      id, source, target, ...opts,
    });

    it('compareNodes: same-size maps with identical nodes → forEach runs (no early exit)', async () => {
      hoisted.nodeMap = new Map([['s1', makeN('s1')]]);
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      // Rerender with same map → compare(prev, next) called; compareNodes forEach runs
      rerender();
    });

    it('compareNodes: different-size maps → early false return before forEach', async () => {
      hoisted.nodeMap = new Map([['s1', makeN('s1')]]);
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      // Rerender with extra node → compareNodes xs.size !== ys.size branch
      hoisted.nodeMap = new Map([['s1', makeN('s1')], ['s2', makeN('s2')]]);
      rerender();
    });

    it('compareNodes: node in xs not present in ys (same size, different ids)', async () => {
      hoisted.nodeMap = new Map([['s1', makeN('s1')], ['s2', makeN('s2')]]);
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      // Replace s2 with s3 (same size, s2 missing from ys) → !y branch in forEach
      hoisted.nodeMap = new Map([['s1', makeN('s1')], ['s3', makeN('s3')]]);
      rerender();
    });

    it('compareNodes: node with resizing=true → x.resizing branch in forEach', async () => {
      hoisted.nodeMap = new Map([['s1', makeN('s1', { resizing: true })]]);
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      // Rerender with same resizing node → x.resizing truthy branch in forEach
      rerender();
    });

    it('compareNodes: nodes with different widths → width mismatch branch in forEach', async () => {
      hoisted.nodeMap = new Map([['s1', makeN('s1', { width: 100 })]]);
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      hoisted.nodeMap = new Map([['s1', makeN('s1', { width: 200 })]]);
      rerender();
    });

    it('compareEdges: different edge counts → early false return', async () => {
      const s1 = makeN('s1');
      const s2 = makeN('s2');
      hoisted.nodeMap = new Map([['s1', s1], ['s2', s2]]);
      hoisted.edges = [makeE('e1', 's1', 's2')];
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      hoisted.edges = [];
      rerender();
    });

    it('compareEdges: edge in xs missing from ys → !y branch in forEach', async () => {
      const s1 = makeN('s1');
      const s2 = makeN('s2');
      hoisted.nodeMap = new Map([['s1', s1], ['s2', s2]]);
      hoisted.edges = [makeE('e1', 's1', 's2')];
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      // Same size (1 edge) but different id → e1 missing from ys
      hoisted.edges = [makeE('e2', 's1', 's2')];
      rerender();
    });

    it('compareEdges: different source → source/target mismatch branch', async () => {
      const s1 = makeN('s1');
      const s2 = makeN('s2');
      hoisted.nodeMap = new Map([['s1', s1], ['s2', s2]]);
      hoisted.edges = [makeE('e1', 's1', 's2')];
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      // Reverse the edge (s2→s1) so x.source !== y.source without creating a
      // self-loop (s2→s2 would make s2 its own parent in d3-hierarchy → "cycle").
      hoisted.edges = [makeE('e1', 's2', 's1')];
      rerender();
    });

    it('compareEdges: different sourceHandle → sourceHandle mismatch branch', async () => {
      const s1 = makeN('s1');
      const s2 = makeN('s2');
      hoisted.nodeMap = new Map([['s1', s1], ['s2', s2]]);
      hoisted.edges = [makeE('e1', 's1', 's2', { sourceHandle: 'top' })];
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      hoisted.edges = [makeE('e1', 's1', 's2', { sourceHandle: 'bottom' })];
      rerender();
    });

    it('compareEdges: identical edges → all checks pass (forEach runs to completion)', async () => {
      const s1 = makeN('s1');
      const s2 = makeN('s2');
      hoisted.nodeMap = new Map([['s1', s1], ['s2', s2]]);
      // Edge with sourceHandle + targetHandle so those checks are evaluated
      hoisted.edges = [makeE('e1', 's1', 's2', { sourceHandle: 'top', targetHandle: 'left' })];
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      // Rerender with the exact same edges → compareEdges forEach runs to completion
      // exercising the targetHandle equality (else) branch (L318 else)
      rerender();
    });

    it('compareEdges: different targetHandle → targetHandle mismatch branch', async () => {
      const s1 = makeN('s1');
      const s2 = makeN('s2');
      hoisted.nodeMap = new Map([['s1', s1], ['s2', s2]]);
      hoisted.edges = [makeE('e1', 's1', 's2', { targetHandle: 'left' })];
      const { rerender } = renderHook(() => useAutoLayout({ direction: 'TB', spacing: [50, 50] }));
      await waitFor(() => expect(hoisted.mockSetNodes).toHaveBeenCalled());
      hoisted.edges = [makeE('e1', 's1', 's2', { targetHandle: 'right' })];
      rerender();
    });
  });
});
