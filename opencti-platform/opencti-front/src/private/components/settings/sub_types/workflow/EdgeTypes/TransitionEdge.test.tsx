import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/react';
import { Position, type EdgeProps, type XYPosition } from 'reactflow';
import TransitionEdge from './TransitionEdge';
import { getRoutePath } from '../layout/route';

vi.mock('@mui/styles', () => ({
  useTheme: () => ({
    palette: {
      primary: { main: '#1976d2' },
      background: { default: '#121212' },
    },
  }),
}));

const makeProps = (route?: XYPosition[]) => ({
  id: 'edge-1',
  source: 'A',
  target: 'B',
  sourceX: 0,
  sourceY: 0,
  targetX: 100,
  targetY: 100,
  sourcePosition: Position.Bottom,
  targetPosition: Position.Top,
  data: route ? { route } : undefined,
}) as EdgeProps<{ route?: XYPosition[] }>;

const visiblePath = (container: HTMLElement) => container.querySelector('path#edge-1')!.getAttribute('d');

describe('TransitionEdge', () => {
  it('draws the layout route when there is one', () => {
    const route = [{ x: 0, y: 0 }, { x: 0, y: 40 }, { x: 100, y: 40 }, { x: 100, y: 100 }];
    const { container } = render(<svg><TransitionEdge {...makeProps(route)} /></svg>);
    expect(visiblePath(container)).toBe(getRoutePath(route)[0]);
  });

  it('falls back to a smoothstep path before the first layout', () => {
    const { container } = render(<svg><TransitionEdge {...makeProps()} /></svg>);
    expect(visiblePath(container)).toMatch(/^M ?0[ ,]0/);
  });
});
