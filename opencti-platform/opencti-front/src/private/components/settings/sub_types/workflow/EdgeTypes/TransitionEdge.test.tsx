import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/react';
import TransitionEdge from './TransitionEdge';
import type { EdgeProps } from 'reactflow';

vi.mock('reactflow', async () => {
  const actual = await vi.importActual('reactflow');
  return {
    ...actual,
    getSmoothStepPath: vi.fn(() => ['M 0 0 L 100 100', 50, 50, 0, 0]),
  };
});

vi.mock('@mui/styles', () => ({
  useTheme: () => ({
    palette: {
      mode: 'dark',
      primary: { main: '#1976d2' },
      background: { default: '#121212' },
    },
  }),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const defaultProps = {
  id: 'edge-1',
  sourceX: 0,
  sourceY: 0,
  targetX: 100,
  targetY: 100,
  sourcePosition: 'bottom',
  targetPosition: 'top',
  markerEnd: 'url(#arrow)',
  data: {},
  source: 'n1',
  target: 'n2',
  selected: false,
} as unknown as EdgeProps;

const renderEdge = (props = defaultProps) =>
  render(
    <svg>
      <TransitionEdge {...props} />
    </svg>,
  );

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('TransitionEdge', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('default rendering', () => {
    it('renders the main edge path with the given id', () => {
      const { container } = renderEdge();
      expect(container.querySelector(`path#${defaultProps.id}`)).toBeInTheDocument();
    });

    it('renders a transparent hit-target path for pointer events', () => {
      const { container } = renderEdge();
      const paths = container.querySelectorAll('path');
      const hitTarget = Array.from(paths).find(
        (p) => p.getAttribute('stroke') === 'transparent',
      );
      expect(hitTarget).toBeDefined();
    });

    it('renders with strokeWidth 1 when not hovered', () => {
      const { container } = renderEdge();
      const path = container.querySelector(`path#${defaultProps.id}`) as SVGPathElement;
      expect(path.style.strokeWidth).toBe('1');
    });

    it('does not show the hover indicator by default', () => {
      const { container } = renderEdge();
      expect(container.querySelector('text')).not.toBeInTheDocument();
    });
  });

  describe('hover interactions', () => {
    it('shows the "+" indicator when mouse enters', () => {
      const { container } = renderEdge();
      const outerG = container.querySelector('g') as SVGGElement;
      fireEvent.mouseEnter(outerG);
      const plus = container.querySelector('text');
      expect(plus).toBeInTheDocument();
      expect(plus?.textContent).toBe('+');
    });

    it('changes strokeWidth to 2 when hovered', () => {
      const { container } = renderEdge();
      const outerG = container.querySelector('g') as SVGGElement;
      fireEvent.mouseEnter(outerG);
      const path = container.querySelector(`path#${defaultProps.id}`) as SVGPathElement;
      expect(path.style.strokeWidth).toBe('2');
    });

    it('positions the hover indicator at the edge centre returned by getSmoothStepPath', () => {
      const { container } = renderEdge();
      const outerG = container.querySelector('g') as SVGGElement;
      fireEvent.mouseEnter(outerG);
      // The inner <g> should contain translate(50, 50) — centre values from mock
      const innerG = container.querySelector('g g');
      expect(innerG?.getAttribute('transform')).toBe('translate(50, 50)');
    });

    it('hides the "+" indicator after mouse leaves', () => {
      const { container } = renderEdge();
      const outerG = container.querySelector('g') as SVGGElement;
      fireEvent.mouseEnter(outerG);
      expect(container.querySelector('text')).toBeInTheDocument();
      fireEvent.mouseLeave(outerG);
      expect(container.querySelector('text')).not.toBeInTheDocument();
    });

    it('resets strokeWidth to 1 after mouse leaves', () => {
      const { container } = renderEdge();
      const outerG = container.querySelector('g') as SVGGElement;
      fireEvent.mouseEnter(outerG);
      fireEvent.mouseLeave(outerG);
      const path = container.querySelector(`path#${defaultProps.id}`) as SVGPathElement;
      expect(path.style.strokeWidth).toBe('1');
    });
  });
});
