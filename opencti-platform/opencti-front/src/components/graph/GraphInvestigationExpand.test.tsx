import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { graphNode } from '../../utils/tests/graphTestData';
import { GraphProvider, useGraphContext } from './GraphContext';
import Graph from './Graph';
import type { GraphNode } from './graph.types';
import type { ObjectToParse } from './utils/useGraphParser';

// The canvas cannot draw in jsdom: the library stands in, keeping the handlers the graph gives it.
const canvas = vi.hoisted(() => ({ onNodeClick: undefined as undefined | ((node: GraphNode, event: Partial<MouseEvent>) => void) }));
vi.mock('react-force-graph-2d', async () => {
  const { forwardRef } = await import('react');
  return {
    default: forwardRef((props: { onNodeClick: typeof canvas.onNodeClick }, _ref) => {
      canvas.onNodeClick = props.onNodeClick;
      return null;
    }),
  };
});
vi.mock('react-force-graph-3d', () => ({ default: () => null }));
// The drag drawing a relationship between two entities: only whether it listens matters here.
const relationDrag = vi.hoisted(() => ({ activated: undefined as boolean | undefined }));
vi.mock('./components/RelationSelection', () => ({
  default: ({ activated }: { activated: boolean }) => {
    relationDrag.activated = activated;
    return null;
  },
}));
vi.mock('../../utils/hooks/useResizeObserver', () => ({ default: () => ({ width: 800, height: 600 }) }));

const ExpandState = () => {
  const { graphState } = useGraphContext();
  return (
    <>
      <span>{graphState.isExpandOpen ? 'expand open' : 'expand closed'}</span>
      <span>{`${graphState.selectedNodes.length} selected`}</span>
    </>
  );
};

const click = { ctrlKey: false, shiftKey: false, altKey: false, metaKey: false, button: 0 };

const doubleClick = (node: GraphNode) => act(() => {
  canvas.onNodeClick?.(node, click);
  canvas.onNodeClick?.(node, click);
});

const VIEW_ONLY = 'You have view access to this investigation';
const emotet = { id: 'malware', entity_type: 'Malware', name: 'Emotet', parent_types: ['Stix-Domain-Object'] } as unknown as ObjectToParse;
const apt = { id: 'intrusion-set', entity_type: 'Intrusion-Set', name: 'APT-X', parent_types: ['Stix-Domain-Object'] } as unknown as ObjectToParse;

const openMenuFromKeyboard = (container: HTMLElement) => {
  container.querySelectorAll('div').forEach((element) => fireEvent.mouseEnter(element));
  fireEvent.keyDown(document, { key: 'F10', shiftKey: true });
};

const renderGraph = (editDisabledReason?: string, objects: ObjectToParse[] = []) => {
  const parentRef = { current: document.createElement('div') };
  return testRender(
    <GraphProvider objects={objects} context="investigation" editDisabledReason={editDisabledReason}>
      <Graph parentRef={parentRef} />
      <ExpandState />
    </GraphProvider>,
  );
};

describe('Graph of an investigation', () => {
  it('opens the expansion on a double click for an editor', () => {
    renderGraph();
    doubleClick(graphNode({ id: 'malware' }));
    expect(screen.getByText('expand open')).toBeInTheDocument();
  });

  it('keeps the expansion closed on a double click for a view only member, and the entity selected', () => {
    renderGraph(VIEW_ONLY);
    doubleClick(graphNode({ id: 'malware' }));
    expect(screen.getByText('expand closed')).toBeInTheDocument();
    expect(screen.getByText('1 selected')).toBeInTheDocument();
  });

  it('draws relationships between entities for an editor only', () => {
    renderGraph();
    expect(relationDrag.activated).toBe(true);
    renderGraph(VIEW_ONLY);
    expect(relationDrag.activated).toBe(false);
  });

  it('disables creating a relationship from the menu of a view only member, saying why', async () => {
    const { container } = renderGraph(VIEW_ONLY, [emotet, apt]);
    act(() => {
      canvas.onNodeClick?.(graphNode({ id: 'malware' }), click);
      canvas.onNodeClick?.(graphNode({ id: 'intrusion-set' }), { ...click, shiftKey: true });
    });
    openMenuFromKeyboard(container);

    const relate = await screen.findByRole('menuitem', { name: /^Create a relationship/ });
    expect(relate).toHaveAttribute('aria-disabled', 'true');
    expect(relate).toHaveTextContent(VIEW_ONLY);
  });

  it('disables "Expand this entity" in the menu of a view only member, saying why', async () => {
    const { container } = renderGraph(VIEW_ONLY, [emotet]);
    act(() => canvas.onNodeClick?.(graphNode({ id: 'malware' }), click));
    openMenuFromKeyboard(container);

    const expand = await screen.findByRole('menuitem', { name: /Expand this entity/ });
    expect(expand).toHaveAttribute('aria-disabled', 'true');
    expect(expand).toHaveTextContent(VIEW_ONLY);
  });
});
