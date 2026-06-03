import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen } from '@testing-library/react';
import TransitionNode from './TransitionNode';
import testRender from '../../../../../../utils/tests/test-render';
import type { Edge, NodeProps, Position } from 'reactflow';
import { CommentMode } from '../utils';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------
const mockGetEdges = vi.fn<() => Edge[]>(() => []);

vi.mock('reactflow', () => ({
  Handle: ({ type, style }: { type: string; style?: React.CSSProperties }) => (
    <div data-testid={`handle-${type}`} style={style} />
  ),
  Position: { Top: 'top', Bottom: 'bottom' },
  useReactFlow: () => ({ getEdges: mockGetEdges }),
}));

vi.mock('@mui/styles', () => ({
  useTheme: () => ({
    palette: {
      mode: 'dark',
      background: { paper: '#121212' },
      primary: { main: '#1976d2' },
    },
  }),
}));

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------
const makeProps = (dataOverrides: Record<string, unknown> = {}, id = 'transition-1'): NodeProps => ({
  id,
  data: {
    event: 'approve',
    conditions: undefined,
    actions: undefined,
    comment: undefined,
    ...dataOverrides,
  },
  selected: false,
  type: 'transition',
  xPos: 0,
  yPos: 0,
  zIndex: 0,
  isConnectable: true,
  dragging: false,
  sourcePosition: 'bottom' as Position,
  targetPosition: 'top' as Position,
});

beforeEach(() => {
  mockGetEdges.mockReturnValue([]);
});

// ---------------------------------------------------------------------------
// Comment label
// ---------------------------------------------------------------------------
describe('TransitionNode – comment label', () => {
  it('shows nothing when comment is "disable"', () => {
    testRender(<TransitionNode {...makeProps({ event: 'approve', comment: CommentMode.disabled })} />);
    expect(screen.queryByText(/comment/i)).toBeNull();
  });

  it('shows nothing when comment is undefined', () => {
    testRender(<TransitionNode {...makeProps({ event: 'approve', comment: undefined })} />);
    expect(screen.queryByText(/comment/i)).toBeNull();
  });

  it('shows "comment allowed" when comment is "allowed"', () => {
    testRender(<TransitionNode {...makeProps({ event: 'approve', comment: CommentMode.allowed })} />);
    expect(screen.getByText(/comment allowed/i)).toBeDefined();
  });

  it('shows "comment required" when comment is "required"', () => {
    testRender(<TransitionNode {...makeProps({ event: 'approve', comment: CommentMode.required })} />);
    expect(screen.getByText(/comment required/i)).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// conditionAndActions summary
// ---------------------------------------------------------------------------
describe('TransitionNode – conditions and actions summary', () => {
  it('shows filter count when conditions.filters.filters is non-empty', () => {
    testRender(
      <TransitionNode
        {...makeProps({
          conditions: {
            filters: {
              filters: [{ key: 'name', values: ['foo'] }],
              filterGroups: [],
            },
          },
        })}
      />,
    );
    expect(screen.getByText(/1 conditions/i)).toBeInTheDocument();
  });

  it('counts filterGroups towards total conditions', () => {
    testRender(
      <TransitionNode
        {...makeProps({
          conditions: {
            filters: {
              filters: [],
              filterGroups: [{}],
            },
          },
        })}
      />,
    );
    expect(screen.getByText(/1 conditions/i)).toBeInTheDocument();
  });

  it('shows action count when actions array is non-empty', () => {
    testRender(
      <TransitionNode
        {...makeProps({
          actions: [{ type: 'validateDraft' }],
        })}
      />,
    );
    expect(screen.getByText(/1 actions/i)).toBeInTheDocument();
  });

  it('shows both conditions and actions with separator', () => {
    testRender(
      <TransitionNode
        {...makeProps({
          conditions: {
            filters: {
              filters: [{ key: 'name', values: [] }],
              filterGroups: [],
            },
          },
          actions: [{ type: 'validateDraft' }, { type: 'updateAuthorizedMembers' }],
        })}
      />,
    );
    expect(screen.getByText(/1 conditions/i)).toBeInTheDocument();
    expect(screen.getByText(/2 actions/i)).toBeInTheDocument();
    expect(screen.getByText(/\|/)).toBeInTheDocument();
  });

  it('shows nothing when conditions and actions are both absent', () => {
    testRender(
      <TransitionNode
        {...makeProps({ conditions: undefined, actions: undefined })}
      />,
    );
    expect(screen.queryByText(/conditions/i)).toBeNull();
    expect(screen.queryByText(/actions/i)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Handle visibility (hasIncomingEdge / hasOutgoingEdge)
// ---------------------------------------------------------------------------
describe('TransitionNode – handle visibility', () => {
  it('hides the target handle when an incoming edge exists', () => {
    mockGetEdges.mockReturnValue([{ id: 'e1', source: 'status-1', target: 'transition-1' }] as Edge[]);
    testRender(<TransitionNode {...makeProps({}, 'transition-1')} />);
    const targetHandle = screen.getByTestId('handle-target');
    expect(targetHandle.style.visibility).toBe('hidden');
  });

  it('shows the target handle when no incoming edge exists', () => {
    mockGetEdges.mockReturnValue([]);
    testRender(<TransitionNode {...makeProps({}, 'transition-1')} />);
    const targetHandle = screen.getByTestId('handle-target');
    expect(targetHandle.style.visibility).toBe('visible');
  });

  it('hides the source handle when an outgoing edge exists', () => {
    mockGetEdges.mockReturnValue([{ id: 'e1', source: 'transition-1', target: 'status-2' }] as Edge[]);
    testRender(<TransitionNode {...makeProps({}, 'transition-1')} />);
    const sourceHandle = screen.getByTestId('handle-source');
    expect(sourceHandle.style.visibility).toBe('hidden');
  });

  it('shows the source handle when no outgoing edge exists', () => {
    mockGetEdges.mockReturnValue([]);
    testRender(<TransitionNode {...makeProps({}, 'transition-1')} />);
    const sourceHandle = screen.getByTestId('handle-source');
    expect(sourceHandle.style.visibility).toBe('visible');
  });
});

// ---------------------------------------------------------------------------
// isBackwardTransition
// ---------------------------------------------------------------------------
describe('TransitionNode – isBackwardTransition', () => {
  // Chain: status-a → t-fwd → status-b → t-back(our node) → status-a
  // status-a IS an ancestor of status-b, so t-back is a backward transition.
  const backwardEdges: Edge[] = [
    { id: 'e1', source: 'status-a', target: 't-fwd' },
    { id: 'e2', source: 't-fwd', target: 'status-b' },
    { id: 'e3', source: 'status-b', target: 't-back' }, // incoming to our node
    { id: 'e4', source: 't-back', target: 'status-a' }, // outgoing from our node
  ] as Edge[];

  it('detects a backward transition and swaps handle positions', () => {
    mockGetEdges.mockReturnValue(backwardEdges);
    testRender(<TransitionNode {...makeProps({}, 't-back')} />);
    // For a backward transition, the target handle should be at Position.Bottom ('bottom')
    // and the source handle at Position.Top ('top').
    // Our mock renders Handle with the position passed as a style key.
    // We can verify via the inline style key set on the handle element.
    const targetHandle = screen.getByTestId('handle-target');
    const sourceHandle = screen.getByTestId('handle-source');
    // The style object uses [isBackwardTransition ? 'bottom' : 'top']: -2
    // For backward: target style has `bottom: -2`, source style has `top: -2`
    expect(targetHandle.style.bottom).toBe('-2px');
    expect(sourceHandle.style.top).toBe('-2px');
  });

  it('does not detect a backward transition for a forward chain', () => {
    // Simple forward chain: status-a → t-fwd → status-b (t-fwd is NOT backward)
    mockGetEdges.mockReturnValue([
      { id: 'e1', source: 'status-a', target: 't-fwd' },
      { id: 'e2', source: 't-fwd', target: 'status-b' },
    ] as Edge[]);
    testRender(<TransitionNode {...makeProps({}, 't-fwd')} />);
    // Forward: target handle style has `top: -2`, source handle style has `bottom: -2`
    const targetHandle = screen.getByTestId('handle-target');
    const sourceHandle = screen.getByTestId('handle-source');
    expect(targetHandle.style.top).toBe('-2px');
    expect(sourceHandle.style.bottom).toBe('-2px');
  });

  it('returns false when the node has no outgoing edge', () => {
    mockGetEdges.mockReturnValue([
      { id: 'e1', source: 'status-a', target: 't-back' }, // only incoming
    ] as Edge[]);
    testRender(<TransitionNode {...makeProps({}, 't-back')} />);
    // No outgoing edge → isBackwardTransition = false → normal (forward) handle positions
    const targetHandle = screen.getByTestId('handle-target');
    expect(targetHandle.style.top).toBe('-2px');
  });
});
