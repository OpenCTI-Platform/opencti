import type { MutableRefObject } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useGraphLayoutEngine, { type GraphLayoutRequest } from './useGraphLayoutEngine';
import type { GraphRef2D } from '../GraphContext';
import { graphNode } from '../../../utils/tests/graphTestData';

describe('useGraphLayoutEngine', () => {
  it('stops repainting every frame when its layout is turned off during the transition', () => {
    // The drawn nodes are memoized by the graph: the same array from one render to the next.
    const nodes = [graphNode({ id: 'a', x: 0, y: 0 })];
    const graphRef = { current: { d3ReheatSimulation: vi.fn(), zoomToFit: vi.fn() } } as unknown as MutableRefObject<GraphRef2D | undefined>;
    const tiers: GraphLayoutRequest = { key: 'tiers', compute: () => new Map([['a', { x: 100, y: 0 }]]) };
    type Props = { layout: GraphLayoutRequest | null; enabled: boolean };
    const initialProps: Props = { layout: tiers, enabled: true };
    const { result, rerender } = renderHook(
      ({ layout, enabled }: Props) => useGraphLayoutEngine({
        graphRef,
        nodes,
        shapeSignature: 'a',
        layout,
        enabled,
        savedPositions: {},
      }),
      { initialProps },
    );
    expect(result.current.animating).toBe(true);
    rerender({ layout: null, enabled: true });
    expect(result.current.animating).toBe(false);

    rerender({ layout: { ...tiers, key: 'tiers-again' }, enabled: true });
    expect(result.current.animating).toBe(true);
    // Switched to 3D: the engine is disabled.
    rerender({ layout: { ...tiers, key: 'tiers-again' }, enabled: false });
    expect(result.current.animating).toBe(false);
  });

  it('gives the nodes their saved pins back when the 2D graph is left, and keeps the layout pins while data loads', () => {
    const nodes = [graphNode({ id: 'a', x: 0, y: 0 }), graphNode({ id: 'b', x: 0, y: 0 })];
    const graphRef = { current: { d3ReheatSimulation: vi.fn(), zoomToFit: vi.fn() } } as unknown as MutableRefObject<GraphRef2D | undefined>;
    const tiers: GraphLayoutRequest = { key: 'tiers', compute: () => new Map([['a', { x: 100, y: 0 }], ['b', { x: 200, y: 0 }]]) };
    type Props = { enabled: boolean; released: boolean };
    const { result, rerender } = renderHook(
      ({ enabled, released }: Props) => useGraphLayoutEngine({
        graphRef,
        nodes,
        shapeSignature: 'a|b',
        layout: tiers,
        enabled,
        released,
        savedPositions: { a: { id: 'a', x: 5, y: 6 } },
      }),
      { initialProps: { enabled: true, released: false } },
    );
    expect(result.current.targets?.get('b')).toEqual({ x: 200, y: 0 });
    // Pinned by the layout, as at the end of its transition.
    nodes.forEach((node) => Object.assign(node, { fx: 1, fy: 1 }));
    rerender({ enabled: false, released: false });
    expect(nodes.map((node) => node.fx)).toEqual([1, 1]);
    rerender({ enabled: false, released: true });
    expect(nodes.map((node) => [node.fx, node.fy])).toEqual([[5, 6], [undefined, undefined]]);
    expect(result.current.targets).toBeNull();
    // Back in 2D: the layout applies afresh.
    rerender({ enabled: true, released: false });
    expect(result.current.animating).toBe(true);
    expect(result.current.targets?.get('a')).toEqual({ x: 100, y: 0 });
  });
});
