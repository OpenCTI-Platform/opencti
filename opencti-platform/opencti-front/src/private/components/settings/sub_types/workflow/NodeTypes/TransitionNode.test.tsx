import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen } from '@testing-library/react';
import TransitionNode from './TransitionNode';
import testRender from '../../../../../../utils/tests/test-render';
import type { Edge, NodeProps } from 'reactflow';

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
  sourcePosition: 'bottom' as any,
  targetPosition: 'top' as any,
});

beforeEach(() => {
  mockGetEdges.mockReturnValue([]);
});

// ---------------------------------------------------------------------------
// Comment label
// ---------------------------------------------------------------------------
describe('TransitionNode – comment label', () => {
  it('shows nothing when comment is "disable"', () => {
    testRender(<TransitionNode {...makeProps({ event: 'approve', comment: 'disable' })} />);
    expect(screen.queryByText(/comment/i)).toBeNull();
  });

  it('shows nothing when comment is undefined', () => {
    testRender(<TransitionNode {...makeProps({ event: 'approve', comment: undefined })} />);
    expect(screen.queryByText(/comment/i)).toBeNull();
  });

  it('shows "comment allowed" when comment is "allowed"', () => {
    testRender(<TransitionNode {...makeProps({ event: 'approve', comment: 'allowed' })} />);
    expect(screen.getByText(/comment allowed/i)).toBeDefined();
  });

  it('shows "comment required" when comment is "required"', () => {
    testRender(<TransitionNode {...makeProps({ event: 'approve', comment: 'required' })} />);
    expect(screen.getByText(/comment required/i)).toBeDefined();
  });
});
