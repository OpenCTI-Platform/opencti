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
});
