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
    syncActions: undefined,
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
// Direction hint from the layout
// ---------------------------------------------------------------------------
describe('TransitionNode – direction', () => {
  it('puts the target handle at the bottom when the layout marks it backward', () => {
    testRender(<TransitionNode {...makeProps({ layout: { backward: true, lane: 'right', rank: 3 } })} />);
    expect(screen.getByTestId('handle-target').style.bottom).toBe('-2px');
  });

  it('keeps the target handle on top without a layout hint, whatever the edges say', () => {
    // An ancestor walk would call this backward (B -> t -> A, A -> B); the hint is the only source now.
    mockGetEdges.mockReturnValue([
      { id: 'a', source: 'A', target: 'B' },
      { id: 'b', source: 'B', target: 'transition-1' },
      { id: 'c', source: 'transition-1', target: 'A' },
    ] as Edge[]);
    testRender(<TransitionNode {...makeProps()} />);
    expect(screen.getByTestId('handle-target').style.top).toBe('-2px');
  });
});

// ---------------------------------------------------------------------------
// Hover highlight
// ---------------------------------------------------------------------------
describe('TransitionNode – highlight', () => {
  it('draws a 1.5px border in the accent colour and thickens its label while highlighted', () => {
    const { container } = testRender(<TransitionNode {...makeProps({ highlighted: true })} />);
    const hexagon = container.querySelector('path')!;
    expect(hexagon.getAttribute('stroke')).toBe('#1976d2');
    expect(hexagon.getAttribute('stroke-width')).toBe('1.5');
    expect(screen.getByText('Approve').parentElement!.style.textShadow).not.toBe('');
  });

  it('keeps a 1px neutral border and a plain label otherwise', () => {
    const { container } = testRender(<TransitionNode {...makeProps()} />);
    const hexagon = container.querySelector('path')!;
    expect(hexagon.getAttribute('stroke-width')).toBe('1');
    expect(hexagon.getAttribute('stroke')).not.toBe('#1976d2');
    expect(screen.getByText('Approve').parentElement!.style.textShadow).toBe('');
  });
});
