import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Position, type EdgeProps, type XYPosition } from 'reactflow';
import TransitionEdge from './TransitionEdge';
import { getRoutePath } from '../layout/route';
import { WorkflowEdgeActionsContext } from './WorkflowEdgeActionsContext';
import { HoverHighlightContext } from '../hoverHighlight';

vi.mock('../../../../../../components/i18n', () => ({
  useFormatter: () => ({ t_i18n: (key: string) => key }),
}));

vi.mock('@mui/styles', () => ({
  useTheme: () => ({
    palette: {
      primary: { main: '#1976d2' },
      background: { default: '#121212' },
      error: { main: '#d32f2f' },
    },
  }),
}));

const makeProps = (route?: XYPosition[], selected = false) => ({
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
  selected,
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

  const withHover = (litEdgeId: string) => (
    <HoverHighlightContext.Provider value={{ nodeIds: new Set(), edgeIds: new Set([litEdgeId]) }}>
      <svg><TransitionEdge {...makeProps()} /></svg>
    </HoverHighlightContext.Provider>
  );

  it('fades the whole edge while it is outside the hovered neighbourhood', () => {
    const { container } = render(withHover('another-edge'));
    expect(container.querySelector<SVGGElement>('svg > g')!.style.opacity).toBe('0.3');
  });

  it('draws a 1.5px stroke while it is lit', () => {
    const { container } = render(withHover('edge-1'));
    expect(container.querySelector<SVGPathElement>('path#edge-1')!.style.strokeWidth).toBe('1.5');
  });

  describe('edge menu', () => {
    const renderWithActions = () => {
      const actions = { insertStatus: vi.fn(), deleteConnection: vi.fn() };
      const view = render(
        <WorkflowEdgeActionsContext.Provider value={actions}>
          <svg><TransitionEdge {...makeProps([{ x: 0, y: 0 }, { x: 0, y: 100 }])} /></svg>
        </WorkflowEdgeActionsContext.Provider>,
      );
      return { actions, view };
    };
    const openFromBadge = async () => {
      fireEvent.mouseEnter(document.querySelector('svg > g')!);
      await userEvent.click(screen.getByRole('button', { name: 'Edge actions' }));
    };

    it('shows the badge while the edge is selected, so the keyboard can reach the menu', () => {
      // React Flow selects a focused edge on Enter or Space; the badge then joins the Tab order.
      render(<svg><TransitionEdge {...makeProps([{ x: 0, y: 0 }, { x: 0, y: 100 }], true)} /></svg>);
      expect(screen.getByRole('button', { name: 'Edge actions' })).toBeInTheDocument();
    });

    it('separates the destructive row from the others', async () => {
      renderWithActions();
      await openFromBadge();
      expect(screen.getByRole('separator')).toBeInTheDocument();
    });

    it('offers to insert a status or delete the connection from the badge', async () => {
      renderWithActions();
      await openFromBadge();
      expect(screen.getAllByRole('menuitem').map((item) => item.textContent)).toEqual(['Insert status here', 'Delete connection']);
    });

    it('shows an outlined badge rather than a filled one', () => {
      renderWithActions();
      fireEvent.mouseEnter(document.querySelector('svg > g')!);
      const badge = screen.getByRole('button', { name: 'Edge actions' });
      expect(badge.className).toContain('border-filigran-brand-primary-transparency-55');
      expect(badge.className).not.toContain('bg-filigran-brand-primary ');
    });

    it('opens the same menu when the edge itself is clicked', async () => {
      const { view } = renderWithActions();
      await userEvent.click(view.container.querySelector('path[stroke="transparent"]')!);
      expect(screen.getByRole('menuitem', { name: 'Delete connection' })).toBeInTheDocument();
    });

    it('inserts a status on this edge', async () => {
      const { actions } = renderWithActions();
      await openFromBadge();
      await userEvent.click(screen.getByRole('menuitem', { name: 'Insert status here' }));
      expect(actions.insertStatus).toHaveBeenCalledWith({ id: 'edge-1', source: 'A', target: 'B' });
    });

    it('deletes this connection', async () => {
      const { actions } = renderWithActions();
      await openFromBadge();
      await userEvent.click(screen.getByRole('menuitem', { name: 'Delete connection' }));
      expect(actions.deleteConnection).toHaveBeenCalledWith('edge-1');
    });
  });
});
