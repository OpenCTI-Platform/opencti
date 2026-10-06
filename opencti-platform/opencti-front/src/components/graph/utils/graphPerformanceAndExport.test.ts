import { beforeAll, describe, expect, it } from 'vitest';
import { createTheme, ThemeOptions } from '@mui/material/styles';
import ThemeDark from '../../ThemeDark';
import { buildGraphPalette } from './graphPalette';
import { computeLinkCurvatures, linkEndsKey } from './graphGeometry';
import { layeredLayout, radialLayout, tierLayout } from './graphLayouts';
import { levelOfDetail, paintGraphLink, paintGraphNode } from './graphPainting';
import { renderGraphImage } from './graphExport';
import { createRecordingContext } from '../../../utils/tests/recordingCanvasContext';
import { graphLink, graphNode, installPath2DStub } from '../../../utils/tests/graphTestData';
import type { GraphLink, GraphNode } from '../graph.types';

const palette = buildGraphPalette(createTheme(ThemeDark() as ThemeOptions));
const TYPES = ['Intrusion-Set', 'Malware', 'Attack-Pattern', 'Indicator', 'IPv4-Addr', 'Sector', 'Country'];

/** A pseudo-random but fixed graph: the same 2,000 nodes and 4,000 links at every run. */
const largeGraph = (nodeCount: number, linkCount: number) => {
  let seed = 42;
  const random = () => {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    return seed / 2147483648;
  };
  const nodes: GraphNode[] = Array.from({ length: nodeCount }, (_, i) => graphNode({
    id: `n${i}`,
    label: `Entity number ${i}`,
    entity_type: TYPES[i % TYPES.length],
    x: random() * 3000,
    y: random() * 3000,
    markedBy: i % 5 === 0 ? [{ id: 'tlp', definition: 'TLP:AMBER', x_opencti_color: '#ffc000' }] : [],
  }));
  const links: GraphLink[] = Array.from({ length: linkCount }, (_, i) => {
    const source = nodes[Math.floor(random() * nodeCount)];
    const target = nodes[(Number(source.id.slice(1)) + 1 + Math.floor(random() * 50)) % nodeCount];
    return graphLink(source, target, { id: `l${i}`, confidence: i % 7 === 0 ? 20 : 80 });
  });
  return { nodes, links };
};

/** A context doing nothing, so the timing measures the painter's own work, not a canvas. */
const noopContext = () => new Proxy({ measureText: (text: string) => ({ width: text.length * 2 }) }, {
  get: (target, property: string) => (property in target ? target[property as 'measureText'] : () => undefined),
  set: () => true,
}) as unknown as CanvasRenderingContext2D;

const elapsed = (run: () => void) => {
  const start = performance.now();
  run();
  return performance.now() - start;
};

beforeAll(installPath2DStub);

describe('performance on 2,000 nodes and 4,000 links', () => {
  const { nodes, links } = largeGraph(2000, 4000);
  const ends = links.map((link) => ({ id: link.id, sourceId: link.source_id, targetId: link.target_id }));
  const curvatureKey = (link: (typeof links)[number]) => linkEndsKey({ id: link.id, sourceId: link.source_id, targetId: link.target_id });

  it('computes every layout within a fraction of a second', () => {
    expect(elapsed(() => layeredLayout(nodes, ends, 'lr'))).toBeLessThan(1500);
    expect(elapsed(() => tierLayout(nodes, ends, (node) => TYPES.indexOf(node.entity_type ?? '')))).toBeLessThan(1500);
    expect(elapsed(() => radialLayout(nodes, ends, null))).toBeLessThan(1000);
  });

  it('paints a full frame with every detail within an animation budget', () => {
    const ctx = noopContext();
    const curvatures = computeLinkCurvatures(ends);
    const detail = levelOfDetail(4, 10);
    const visual = { selected: false, preview: false, hovered: false, faded: false, onPath: false };
    // Warm the glyph and path caches first, like the first frame on screen does.
    nodes.slice(0, TYPES.length).forEach((node) => paintGraphNode(ctx, node, { palette, globalScale: 4, detail, visual }));
    const time = elapsed(() => {
      links.forEach((link) => paintGraphLink(ctx, link, {
        palette, globalScale: 4, detail, visual, color: palette.link, curvature: curvatures.get(curvatureKey(link))?.curvature ?? 0, rotation: 0,
      }));
      nodes.forEach((node) => paintGraphNode(ctx, node, { palette, globalScale: 4, detail, visual }));
    });
    // Measured around 30 ms on a laptop; the bound leaves room for slower CI machines.
    expect(time).toBeLessThan(400);
  });

  it('draws no text and no icon at overview zoom, which keeps large graphs fluid', () => {
    const ctx = createRecordingContext();
    const detail = levelOfDetail(0.2, nodes.length);
    const visual = { selected: false, preview: false, hovered: false, faded: false, onPath: false };
    nodes.slice(0, 200).forEach((node) => paintGraphNode(ctx, node, { palette, globalScale: 0.2, detail, visual }));
    expect(ctx.texts()).toEqual([]);
    expect(ctx.callsOf('fill').filter((call) => call.args.length > 0)).toEqual([]);
  });
});

describe('renderGraphImage', () => {
  const a = graphNode({ id: 'a', x: 0, y: 0, label: 'APT-X', entity_type: 'Intrusion-Set', color: '#ff9800' });
  const b = graphNode({ id: 'b', x: 120, y: 40, label: 'Emotet' });
  const ctx = createRecordingContext();
  const canvas = { width: 0, height: 0, getContext: () => ctx } as unknown as HTMLCanvasElement;
  const input = {
    nodes: [a, b],
    links: [graphLink(a, b)],
    palette,
    title: 'Report graph',
    subtitle: '2 entities',
    typeLabel: (node: GraphNode) => node.entity_type,
    badgesOf: () => [],
    linkColor: () => palette.link,
    legend: {
      title: 'Legend',
      entities: [{ label: 'Intrusion set', color: '#ff9800', count: 1 }, { label: 'Malware', color: '#f0b60a', count: 1 }],
      lineStyles: [{ label: 'Inferred relationship', kind: 'inferred' as const }],
    },
  };

  it('draws the whole graph, its title and its legend on a canvas sized for print', () => {
    const rendered = renderGraphImage(input, () => canvas);
    expect(rendered).toBe(canvas);
    expect(canvas.width).toBeGreaterThan(1000);
    expect(canvas.width).toBeLessThanOrEqual(8000);
    expect(canvas.height).toBeLessThanOrEqual(8000);
    expect(ctx.texts()).toEqual(expect.arrayContaining(['Report graph', '2 entities', 'APT-X', 'Emotet', 'uses', 'Legend', 'Intrusion set', 'Malware', 'Inferred relationship']));
    expect(ctx.callsOf('fillRect')[0].fillStyle).toBe(palette.background);
  });

  it('keeps a huge drawing within the maximum image size', () => {
    const far = graphNode({ id: 'far', x: 50000, y: 50000 });
    const big = { width: 0, height: 0, getContext: () => createRecordingContext() } as unknown as HTMLCanvasElement;
    renderGraphImage({ ...input, nodes: [a, far], links: [] }, () => big);
    expect(big.width).toBeLessThanOrEqual(8000);
    expect(big.height).toBeLessThanOrEqual(8000);
  });

  it('keeps room for the badges of the boundary nodes once a huge drawing is scaled down', () => {
    const recording = createRecordingContext();
    const far = graphNode({ id: 'far', x: 50000, y: 50000 });
    const big = { width: 0, height: 0, getContext: () => recording } as unknown as HTMLCanvasElement;
    renderGraphImage({ ...input, nodes: [a, far], links: [] }, () => big);
    const [scale] = recording.callsOf('scale')[0].args as number[];
    const [x, y] = recording.callsOf('translate')[0].args as number[];
    // The drawing starts at the node at (0, 0), after the 32 px padding and the 72 px header; the
    // badges keep at least 10 px whatever the scale, so the room around it is counted in pixels.
    expect(scale).toBeLessThan(1);
    expect(x - 32).toBeGreaterThanOrEqual(48);
    expect(y - 72).toBeGreaterThanOrEqual(48);
    expect(x + 50000 * scale + 48).toBeLessThanOrEqual(big.width - 280 - 32 + 1);
    expect(big.width).toBeLessThanOrEqual(8000);
    expect(big.height).toBeLessThanOrEqual(8000);
  });

  it('sizes the image on the curves and self-loops reaching beyond the nodes', () => {
    const sizeWith = (curvature: number, links = [graphLink(a, b)]) => {
      const sized = { width: 0, height: 0, getContext: () => createRecordingContext() } as unknown as HTMLCanvasElement;
      renderGraphImage({ ...input, links, curvatureOf: () => ({ curvature, rotation: 0 }) }, () => sized);
      return { width: sized.width, height: sized.height };
    };
    const straight = sizeWith(0);
    expect(sizeWith(0.8).height).toBeGreaterThan(straight.height);
    const selfLoop = sizeWith(1, [graphLink(b, b, { id: 'loop' })]);
    expect(selfLoop.width).toBeGreaterThan(straight.width);
  });

  it('gives nothing to export for an empty graph', () => {
    expect(renderGraphImage({ ...input, nodes: [], links: [] }, () => canvas)).toBeNull();
  });
});
