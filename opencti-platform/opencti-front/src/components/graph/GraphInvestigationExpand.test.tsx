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
      <span>{graphState.isAddEntitiesOpen ? 'add entities open' : 'add entities closed'}</span>
    </>
  );
};

const click = { ctrlKey: false, shiftKey: false, altKey: false, metaKey: false, button: 0 };

const doubleClick = (node: GraphNode) => act(() => {
  canvas.onNodeClick?.(node, click);
  canvas.onNodeClick?.(node, click);
});

const emotet = { id: 'malware', entity_type: 'Malware', name: 'Emotet', parent_types: ['Stix-Domain-Object'] } as unknown as ObjectToParse;
const apt = { id: 'intrusion-set', entity_type: 'Intrusion-Set', name: 'APT-X', parent_types: ['Stix-Domain-Object'] } as unknown as ObjectToParse;

const openMenuFromKeyboard = (container: HTMLElement) => {
  container.querySelectorAll('div').forEach((element) => fireEvent.mouseEnter(element));
  fireEvent.keyDown(document, { key: 'F10', shiftKey: true });
};

const renderGraph = (readOnly?: boolean, objects: ObjectToParse[] = []) => {
  const parentRef = { current: document.createElement('div') };
  return testRender(
    <GraphProvider objects={objects} context="investigation" readOnly={readOnly}>
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

  it('keeps the expansion closed on a double click for a member who cannot change the investigation, and the entity selected', () => {
    renderGraph(true);
    doubleClick(graphNode({ id: 'malware' }));
    expect(screen.getByText('expand closed')).toBeInTheDocument();
    expect(screen.getByText('1 selected')).toBeInTheDocument();
  });

  it('draws relationships between entities for an editor only', () => {
    renderGraph();
    expect(relationDrag.activated).toBe(true);
    renderGraph(true);
    expect(relationDrag.activated).toBe(false);
  });

  it('offers adding entities to an empty investigation for an editor only', async () => {
    renderGraph(true);
    await screen.findByText('Read the documentation');
    expect(screen.queryByRole('button', { name: 'Add entities' })).not.toBeInTheDocument();
    renderGraph();
    fireEvent.click(await screen.findByRole('button', { name: 'Add entities' }));
    expect(screen.getAllByText('add entities open')).toHaveLength(1);
  });

  const openSelectionMenu = (readOnly?: boolean) => {
    const { container } = renderGraph(readOnly, [emotet, apt]);
    act(() => {
      canvas.onNodeClick?.(graphNode({ id: 'malware' }), click);
      canvas.onNodeClick?.(graphNode({ id: 'intrusion-set' }), { ...click, shiftKey: true });
    });
    openMenuFromKeyboard(container);
  };

  const openEntityMenu = (readOnly?: boolean) => {
    const { container } = renderGraph(readOnly, [emotet]);
    act(() => canvas.onNodeClick?.(graphNode({ id: 'malware' }), click));
    openMenuFromKeyboard(container);
  };

  it('offers creating a relationship from the menu of an editor', async () => {
    openSelectionMenu();
    expect(await screen.findByRole('menuitem', { name: /^Create a relationship/ })).toBeInTheDocument();
  });

  it('hides creating a relationship from the menu of a member who cannot change the investigation', async () => {
    openSelectionMenu(true);
    await screen.findByRole('menuitem', { name: /^Hide/ });
    expect(screen.queryByRole('menuitem', { name: /^Create a relationship/ })).not.toBeInTheDocument();
  });

  it('offers "Expand this entity" in the menu of an editor', async () => {
    openEntityMenu();
    expect(await screen.findByRole('menuitem', { name: /Expand this entity/ })).toBeInTheDocument();
  });

  it('hides "Expand this entity" from the menu of a member who cannot change the investigation', async () => {
    openEntityMenu(true);
    await screen.findByRole('menuitem', { name: /Open in a new tab/ });
    expect(screen.queryByRole('menuitem', { name: /Expand this entity/ })).not.toBeInTheDocument();
  });
});
