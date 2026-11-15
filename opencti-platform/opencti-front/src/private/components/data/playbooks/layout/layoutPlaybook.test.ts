import { describe, expect, it } from 'vitest';
import { canonicalOrder, countCrossings, layoutPlaybook, PLAYBOOK_NODE_SIZE } from './layoutPlaybook';
import type { PlaybookLayoutComponent, PlaybookLayoutLink, PlaybookLayoutMode, PlaybookLayoutNode } from './layoutPlaybook';

const COMPONENTS: PlaybookLayoutComponent[] = [
  { id: 'LISTEN', is_entry_point: true, ports: [{ id: 'out', type: 'out' }] },
  { id: 'ENRICH', ports: [{ id: 'in', type: 'in' }, { id: 'out', type: 'out' }] },
  { id: 'AI', ports: [{ id: 'in', type: 'in' }, { id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }] },
  { id: 'MATCH', ports: [{ id: 'in', type: 'in' }, { id: 'out', type: 'out' }, { id: 'no-match', type: 'out' }] },
  { id: 'MANIPULATE', ports: [{ id: 'in', type: 'in' }, { id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }] },
  { id: 'LOG', ports: [{ id: 'in', type: 'in' }, { id: 'out', type: 'out' }] },
  { id: 'INGEST', ports: [{ id: 'in', type: 'in' }] },
];

const node = (id: string, component_id: string, position = { x: 0, y: 0 }): PlaybookLayoutNode => ({ id, component_id, position });
const link = (from: string, port: string, to: string): PlaybookLayoutLink => ({ id: `${from}:${port}->${to}`, from: { id: from, port }, to: { id: to } });

// The report pipeline of the issue screenshots: two-port components whose out and unmodified
// ports both reach the next step (nodes with several incoming links), a filter with a no-match
// branch and an error branch.
const REPORT_PIPELINE = {
  nodes: [
    node('a-listen', 'LISTEN'),
    node('b-scrape', 'ENRICH'),
    node('c-qualify', 'AI'),
    node('d-status', 'MATCH'),
    node('e-log', 'LOG'),
    node('f-extract', 'AI'),
    node('g-rejected', 'INGEST'),
    node('h-processed', 'MANIPULATE'),
    node('i-categorize', 'AI'),
    node('j-ready', 'MANIPULATE'),
    node('k-ingest', 'INGEST'),
  ],
  links: [
    link('a-listen', 'out', 'b-scrape'),
    link('b-scrape', 'out', 'c-qualify'),
    link('c-qualify', 'out', 'd-status'),
    link('c-qualify', 'unmodified', 'e-log'),
    link('d-status', 'out', 'f-extract'),
    link('d-status', 'no-match', 'g-rejected'),
    link('f-extract', 'out', 'h-processed'),
    link('f-extract', 'unmodified', 'h-processed'),
    link('h-processed', 'out', 'i-categorize'),
    link('h-processed', 'unmodified', 'i-categorize'),
    link('i-categorize', 'out', 'j-ready'),
    link('i-categorize', 'unmodified', 'j-ready'),
    link('j-ready', 'out', 'k-ingest'),
    link('j-ready', 'unmodified', 'k-ingest'),
  ],
};

// Small seeded generator (mulberry32) so the random fixtures are the same on every run.
const rng = (seed: number) => {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

// A valid playbook: one entry point, every other node reached from an out port of an earlier node.
const randomPlaybook = (seed: number, size: number) => {
  const random = rng(seed);
  const nodes: PlaybookLayoutNode[] = [node('n000', 'LISTEN')];
  const links: PlaybookLayoutLink[] = [];
  const free: { id: string; port: string }[] = [{ id: 'n000', port: 'out' }];
  const kinds = ['ENRICH', 'AI', 'MATCH', 'MANIPULATE', 'LOG', 'INGEST'];
  for (let i = 1; i < size && free.length > 0; i += 1) {
    const id = `n${String(i).padStart(3, '0')}`;
    const component = kinds[Math.floor(random() * kinds.length)];
    nodes.push(node(id, component, { x: Math.round(random() * 2000), y: Math.round(random() * 2000) }));
    const parent = free.splice(Math.floor(random() * free.length), 1)[0];
    links.push(link(parent.id, parent.port, id));
    // Sometimes a second port joins the same node (several incoming links).
    if (free.length > 0 && random() < 0.2) {
      const extra = free.splice(Math.floor(random() * free.length), 1)[0];
      links.push(link(extra.id, extra.port, id));
    }
    COMPONENTS.find((c) => c.id === component)!.ports!.filter((p) => p.type === 'out').forEach((p) => free.push({ id, port: p.id }));
  }
  return { nodes, links };
};

const shuffle = <T>(list: T[], seed: number): T[] => {
  const random = rng(seed);
  const copy = list.slice();
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
};

const serialise = (positions: Map<string, { x: number; y: number }>) => [...positions.entries()]
  .sort(([a], [b]) => (a < b ? -1 : 1))
  .map(([id, p]) => `${id}@${p.x},${p.y}`)
  .join('|');

const overlaps = (positions: Map<string, { x: number; y: number }>) => {
  const boxes = [...positions.entries()];
  const hits: string[] = [];
  for (let i = 0; i < boxes.length; i += 1) {
    for (let j = i + 1; j < boxes.length; j += 1) {
      const [a, p] = boxes[i];
      const [b, q] = boxes[j];
      if (Math.abs(p.x - q.x) < PLAYBOOK_NODE_SIZE.width && Math.abs(p.y - q.y) < PLAYBOOK_NODE_SIZE.height) hits.push(`${a}/${b}`);
    }
  }
  return hits;
};

const FIXTURES = [
  { name: 'report pipeline', ...REPORT_PIPELINE },
  ...Array.from({ length: 60 }, (_, i) => ({ name: `random ${i + 1}`, ...randomPlaybook(i + 1, 5 + (i % 30)) })),
];
const MODES: PlaybookLayoutMode[] = ['vertical', 'horizontal'];

describe('layoutPlaybook', () => {
  it('lays out an empty playbook as nothing', () => {
    const result = layoutPlaybook([], [], COMPONENTS, { mode: 'vertical' });
    expect(result.positions.size).toBe(0);
  });

  it('gives the same picture whatever the order of nodes and links (shuffled 5 times per fixture and mode)', () => {
    const offenders: string[] = [];
    FIXTURES.forEach((f) => MODES.forEach((mode) => {
      const reference = serialise(layoutPlaybook(f.nodes, f.links, COMPONENTS, { mode }).positions);
      for (let s = 1; s <= 5; s += 1) {
        const shuffled = layoutPlaybook(shuffle(f.nodes, s), shuffle(f.links, s * 7), shuffle(COMPONENTS, s * 13), { mode });
        if (serialise(shuffled.positions) !== reference) offenders.push(`${f.name} ${mode} shuffle ${s}`);
      }
    }));
    expect(offenders).toEqual([]);
  });

  it('ignores saved positions in the automatic modes (a refresh never moves anything)', () => {
    const moved = REPORT_PIPELINE.nodes.map((n, i) => ({ ...n, position: { x: i * 999, y: -i * 37 } }));
    const a = layoutPlaybook(REPORT_PIPELINE.nodes, REPORT_PIPELINE.links, COMPONENTS, { mode: 'vertical' });
    const b = layoutPlaybook(moved, REPORT_PIPELINE.links, COMPONENTS, { mode: 'vertical' });
    expect(serialise(b.positions)).toBe(serialise(a.positions));
  });

  it('positions every node once, without overlap, children below (vertical) or right of (horizontal) their parents', () => {
    const offenders: string[] = [];
    FIXTURES.forEach((f) => MODES.forEach((mode) => {
      const result = layoutPlaybook(f.nodes, f.links, COMPONENTS, { mode });
      f.nodes.filter((n) => !result.positions.has(n.id)).forEach((n) => offenders.push(`${f.name} ${mode}: ${n.id} missing`));
      overlaps(result.positions).forEach((o) => offenders.push(`${f.name} ${mode}: overlap ${o}`));
      f.links.forEach((l) => {
        const p = result.positions.get(l.from.id)!;
        const q = result.positions.get(l.to.id)!;
        const forward = mode === 'vertical' ? q.y > p.y : q.x > p.x;
        if (!forward) offenders.push(`${f.name} ${mode}: ${l.id} goes backward`);
      });
    }));
    expect(offenders).toEqual([]);
  });

  it('places a node with several incoming links once, on the rank after its deepest parent', () => {
    const result = layoutPlaybook(REPORT_PIPELINE.nodes, REPORT_PIPELINE.links, COMPONENTS, { mode: 'vertical' });
    expect(result.ranks.get('h-processed')).toBe(result.ranks.get('f-extract')! + 1);
    expect(result.ranks.get('k-ingest')).toBe(result.ranks.get('j-ready')! + 1);
    // The main chain stays on one vertical line.
    const chain = ['h-processed', 'i-categorize', 'j-ready', 'k-ingest'].map((id) => result.positions.get(id)!.x);
    expect(new Set(chain).size).toBe(1);
  });

  it('draws the report pipeline without any crossing, in both modes', () => {
    MODES.forEach((mode) => {
      const result = layoutPlaybook(REPORT_PIPELINE.nodes, REPORT_PIPELINE.links, COMPONENTS, { mode });
      expect(result.crossings).toBe(0);
      expect(countCrossings(result, REPORT_PIPELINE.links, PLAYBOOK_NODE_SIZE, mode)).toBe(0);
    });
  });

  it('keeps the branches of a port in the port order of the component (out left of unmodified / no-match)', () => {
    const result = layoutPlaybook(REPORT_PIPELINE.nodes, REPORT_PIPELINE.links, COMPONENTS, { mode: 'vertical' });
    expect(result.positions.get('d-status')!.x).toBeLessThan(result.positions.get('e-log')!.x);
    expect(result.positions.get('f-extract')!.x).toBeLessThan(result.positions.get('g-rejected')!.x);
  });

  it('keeps out first and draws no crossing when a step\'s component is not in the catalog (AI agent without XTM One)', () => {
    const withoutAi = COMPONENTS.filter((c) => c.id !== 'AI');
    // Node ids that would put the unmodified branch first if ports were ordered by target id.
    const nodes = REPORT_PIPELINE.nodes.map((n) => (n.id === 'd-status' ? node('z-status', 'MATCH') : n));
    const links = REPORT_PIPELINE.links.map((l) => (l.to.id === 'd-status' ? link(l.from.id, l.from.port, 'z-status')
      : l.from.id === 'd-status' ? link('z-status', l.from.port, l.to.id) : l));
    MODES.forEach((mode) => {
      const result = layoutPlaybook(nodes, links, withoutAi, { mode });
      expect(result.crossings).toBe(0);
    });
    const vertical = layoutPlaybook(nodes, links, withoutAi, { mode: 'vertical' });
    expect(vertical.positions.get('z-status')!.x).toBeLessThan(vertical.positions.get('e-log')!.x);
  });

  it('keeps the saved positions in manual mode and lays out a node without one', () => {
    const nodes = REPORT_PIPELINE.nodes.map((n, i) => (i === 3 ? { ...n, position: null } : { ...n, position: { x: i * 10, y: i * 20 } }));
    const result = layoutPlaybook(nodes, REPORT_PIPELINE.links, COMPONENTS, { mode: 'manual' });
    expect(result.positions.get('a-listen')).toEqual({ x: 0, y: 0 });
    expect(result.positions.get('k-ingest')).toEqual({ x: 100, y: 200 });
    const auto = layoutPlaybook(REPORT_PIPELINE.nodes, REPORT_PIPELINE.links, COMPONENTS, { mode: 'vertical' });
    expect(result.positions.get('d-status')).toEqual(auto.positions.get('d-status'));
  });

  it('opens a legacy definition (several roots, a dangling link, a cycle) without throwing', () => {
    const nodes = [node('r1', 'LISTEN'), node('r2', 'ENRICH'), node('x', 'LOG'), node('y', 'LOG')];
    const links = [link('r1', 'out', 'x'), link('x', 'out', 'y'), link('y', 'out', 'x'), link('ghost', 'out', 'x')];
    const result = layoutPlaybook(nodes, links, COMPONENTS, { mode: 'vertical' });
    expect(result.positions.size).toBe(4);
    expect(overlaps(result.positions)).toEqual([]);
  });

  it('lays out a 150-node playbook quickly', () => {
    const big = randomPlaybook(4242, 150);
    const start = performance.now();
    const result = layoutPlaybook(big.nodes, big.links, COMPONENTS, { mode: 'vertical' });
    expect(result.positions.size).toBe(big.nodes.length);
    expect(performance.now() - start).toBeLessThan(2000);
  });

  it('orders nodes canonically: entry point first, children by port order then id', () => {
    const components = new Map(COMPONENTS.map((c) => [c.id, c]));
    const { nodes } = canonicalOrder(shuffle(REPORT_PIPELINE.nodes, 3), shuffle(REPORT_PIPELINE.links, 5), components);
    expect(nodes.map((n) => n.id).slice(0, 4)).toEqual(['a-listen', 'b-scrape', 'c-qualify', 'd-status']);
  });
});
