import { describe, expect, it } from 'vitest';
import type { LayoutEngine } from './LayoutEngine';
import { withPackedLeaves } from './packLeaves';

// Places every node on its own rank, one under the other, so packing is easy to observe.
const stackEngine: LayoutEngine = {
  layout: (nodes) => new Map(nodes.map((node, index) => [node.id, { x: 0, y: index * 1000 }])),
};

const node = (id: string) => ({ id, width: 100, height: 50 });

describe('withPackedLeaves', () => {
  it('keeps small sibling sets untouched', () => {
    const nodes = ['root', 'a', 'b'].map(node);
    const edges = [{ source: 'root', target: 'a', weight: 1 }, { source: 'root', target: 'b', weight: 1 }];
    expect(withPackedLeaves(stackEngine, () => true).layout(nodes, edges, 'TB')).toEqual(stackEngine.layout(nodes, edges, 'TB'));
  });

  it('lays many leaves of one parent out as a grid', () => {
    const leaves = Array.from({ length: 8 }, (_, index) => `leaf${index}`);
    const nodes = [node('root'), ...leaves.map(node)];
    const edges = leaves.map((leaf) => ({ source: 'root', target: leaf, weight: 1 }));
    const positions = withPackedLeaves(stackEngine, () => true).layout(nodes, edges, 'TB');
    // 8 leaves, TB: ceil(sqrt(16)) = 4 columns, 2 rows, below the root.
    expect(new Set(leaves.map((leaf) => positions.get(leaf)?.x)).size).toBe(4);
    expect(new Set(leaves.map((leaf) => positions.get(leaf)?.y)).size).toBe(2);
    expect(positions.get('leaf5')).toEqual({ x: 124, y: 1074 });
    expect(positions.has('pack:root|true')).toBe(false);
  });

  it('leaves out nodes that are not packable', () => {
    const leaves = Array.from({ length: 8 }, (_, index) => `leaf${index}`);
    const nodes = [node('root'), ...leaves.map(node)];
    const edges = leaves.map((leaf) => ({ source: 'root', target: leaf, weight: 1 }));
    const positions = withPackedLeaves(stackEngine, (id) => id !== 'leaf0').layout(nodes, edges, 'TB');
    expect(positions.get('leaf0')).toEqual({ x: 0, y: 1000 });
  });
});
