import { describe, expect, it } from 'vitest';
import { demoLabels, demoLocation, findDemoNode, isDemoMode } from './graphDemoLocate';
import { NODE_RADIUS, RELATIONSHIP_NODE_RADIUS } from './graphPainting';

const node = (id: string, name: string, x = 10, y = 20, extra = {}) => ({
  id,
  name,
  label: name,
  relationship_type: '',
  x,
  y,
  ...extra,
});

describe('isDemoMode', () => {
  it('reads the demo flag only when it is 1', () => {
    expect(isDemoMode('?demo=1')).toBe(true);
    expect(isDemoMode('?tab=graph&demo=1')).toBe(true);
    expect(isDemoMode('?demo=0')).toBe(false);
    expect(isDemoMode('')).toBe(false);
  });
});

describe('findDemoNode', () => {
  const nodes = [node('a', 'Copper Lantern'), node('b', 'APT-X'), node('c', 'Unplaced', Number.NaN, Number.NaN)];

  it('finds a node by its title, its id, then in any case', () => {
    expect(findDemoNode(nodes, 'Copper Lantern')?.id).toBe('a');
    expect(findDemoNode(nodes, 'b')?.id).toBe('b');
    expect(findDemoNode(nodes, 'copper lantern')?.id).toBe('a');
  });

  it('never finds a node not laid out yet, nor one the graph does not show', () => {
    expect(findDemoNode(nodes, 'Unplaced')).toBeUndefined();
    expect(findDemoNode(nodes, 'Kettle')).toBeUndefined();
  });

  it('lists the labels a recording may name', () => {
    expect(demoLabels(nodes)).toEqual(['Copper Lantern', 'APT-X', 'Unplaced']);
  });
});

describe('demoLocation', () => {
  it('places the node on the page from the canvas corner, its radius drawn at the zoom', () => {
    expect(demoLocation(node('a', 'Copper Lantern'), { x: 300, y: 120 }, { left: 64, top: 180 }, 2)).toEqual({
      x: 364,
      y: 300,
      r: NODE_RADIUS * 2,
      id: 'a',
      label: 'Copper Lantern',
    });
    expect(demoLocation(node('r', 'uses', 0, 0, { relationship_type: 'uses' }), { x: 0, y: 0 }, { left: 0, top: 0 }, 1).r)
      .toBe(RELATIONSHIP_NODE_RADIUS);
  });
});
