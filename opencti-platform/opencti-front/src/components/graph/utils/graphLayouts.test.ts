import { describe, expect, it } from 'vitest';
import { breakCycles, entityTier, hasCycle, layeredLayout, mostConnected, radialLayout, tierLayout } from './graphLayouts';

const nodes = ['a', 'b', 'c', 'd'].map((id) => ({ id }));
const chain = [
  { id: 'ab', sourceId: 'a', targetId: 'b' },
  { id: 'bc', sourceId: 'b', targetId: 'c' },
  { id: 'ad', sourceId: 'a', targetId: 'd' },
];

describe('breakCycles', () => {
  it('reverses only what closes a cycle', () => {
    const links = [...chain, { id: 'ca', sourceId: 'c', targetId: 'a' }];
    const acyclic = breakCycles(['a', 'b', 'c', 'd'], links);
    expect(acyclic.find((l) => l.id === 'ca')).toEqual({ id: 'ca', sourceId: 'a', targetId: 'c' });
    expect(acyclic.find((l) => l.id === 'ab')).toEqual(chain[0]);
  });

  it('reverses only the connector of a nested relationship that closes a cycle', () => {
    // The nested relationship `rel` is drawn as the node `r` between two connectors sharing its id.
    const links = [
      { id: 'rel', sourceId: 'x', targetId: 'r' },
      { id: 'rel', sourceId: 'r', targetId: 'y' },
      { id: 'yx', sourceId: 'y', targetId: 'x' },
    ];
    expect(breakCycles(['r', 'x', 'y'], links)).toEqual([
      { id: 'rel', sourceId: 'r', targetId: 'x' },
      { id: 'rel', sourceId: 'r', targetId: 'y' },
      { id: 'yx', sourceId: 'y', targetId: 'x' },
    ]);
  });
});

describe('hasCycle', () => {
  it('tells a cycle, a link to the node itself included, from a tree', () => {
    expect(hasCycle(['a', 'b', 'c', 'd'], chain)).toBe(false);
    expect(hasCycle(['a', 'b', 'c', 'd'], [...chain, { id: 'ca', sourceId: 'c', targetId: 'a' }])).toBe(true);
    expect(hasCycle(['a', 'b', 'c', 'd'], [...chain, { id: 'dd', sourceId: 'd', targetId: 'd' }])).toBe(true);
    // Two paths to the same node are no cycle.
    expect(hasCycle(['a', 'b', 'c', 'd'], [...chain, { id: 'dc', sourceId: 'd', targetId: 'c' }])).toBe(false);
  });
});

describe('layeredLayout', () => {
  it('places every source before its targets, left to right', () => {
    const positions = layeredLayout(nodes, chain, 'lr');
    const x = (id: string) => positions.get(id)?.x ?? NaN;
    expect(x('a')).toBeLessThan(x('b'));
    expect(x('b')).toBeLessThan(x('c'));
    expect(x('a')).toBeLessThan(x('d'));
  });

  it('reads top to bottom in the vertical mode', () => {
    const positions = layeredLayout(nodes, chain, 'td');
    expect(positions.get('a')?.y).toBeLessThan(positions.get('c')?.y ?? NaN);
  });

  it('lays out cycles and isolated nodes instead of failing', () => {
    const positions = layeredLayout([...nodes, { id: 'e' }], [...chain, { id: 'ca', sourceId: 'c', targetId: 'a' }], 'lr');
    expect(positions.size).toBe(5);
    positions.forEach(({ x, y }) => {
      expect(Number.isFinite(x)).toBe(true);
      expect(Number.isFinite(y)).toBe(true);
    });
  });

  it('gives the same picture whatever the order of the input', () => {
    const first = layeredLayout(nodes, chain, 'lr');
    const second = layeredLayout([...nodes].reverse(), [...chain].reverse(), 'lr');
    expect([...second.entries()].sort()).toEqual([...first.entries()].sort());
  });

  it('never stacks two nodes on the same spot', () => {
    const many = Array.from({ length: 30 }, (_, i) => ({ id: `n${i}` }));
    const star = many.slice(1).map((n) => ({ id: `l-${n.id}`, sourceId: 'n0', targetId: n.id }));
    const positions = [...layeredLayout(many, star, 'lr').values()].map(({ x, y }) => `${x}|${y}`);
    expect(new Set(positions).size).toBe(many.length);
  });
});

describe('tierLayout', () => {
  it('puts threats left of their arsenal and victims on the right', () => {
    const typed = [
      { id: 'victim', entity_type: 'Sector' },
      { id: 'threat', entity_type: 'Intrusion-Set' },
      { id: 'tool', entity_type: 'Malware' },
    ];
    const family: Record<string, string> = { Sector: 'victimology', 'Intrusion-Set': 'allThreats', Malware: 'arsenal' };
    const positions = tierLayout(typed, [], (node) => entityTier(family[node.entity_type ?? '']));
    expect(positions.get('threat')?.x).toBeLessThan(positions.get('tool')?.x ?? NaN);
    expect(positions.get('tool')?.x).toBeLessThan(positions.get('victim')?.x ?? NaN);
  });

  it('puts unknown families last', () => {
    expect(entityTier(null)).toBeGreaterThan(entityTier('analyse'));
  });
});

describe('radialLayout', () => {
  it('centres the chosen node and puts farther nodes on wider rings', () => {
    const positions = radialLayout(nodes, chain, 'a');
    const radius = (id: string) => Math.hypot(positions.get(id)?.x ?? NaN, positions.get(id)?.y ?? NaN);
    expect(radius('a')).toBe(0);
    expect(radius('b')).toBeGreaterThan(0);
    expect(radius('c')).toBeGreaterThan(radius('b'));
  });

  it('centres the most connected node by default and rings unreachable nodes outside', () => {
    const positions = radialLayout([...nodes, { id: 'z' }], chain, null);
    expect(mostConnected(nodes, chain)).toBe('a');
    expect(Math.hypot(positions.get('a')?.x ?? NaN, positions.get('a')?.y ?? NaN)).toBe(0);
    const outer = Math.hypot(positions.get('z')?.x ?? 0, positions.get('z')?.y ?? 0);
    const inner = Math.max(...['b', 'c', 'd'].map((id) => Math.hypot(positions.get(id)?.x ?? 0, positions.get(id)?.y ?? 0)));
    expect(outer).toBeGreaterThan(inner);
  });

  it('lays out nothing without nodes', () => {
    expect(radialLayout([], [], null).size).toBe(0);
  });
});
