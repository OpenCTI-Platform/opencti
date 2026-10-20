import { beforeAll, describe, expect, it } from 'vitest';
import { createTheme, ThemeOptions } from '@mui/material/styles';
import { SpeedOutlined } from '@mui/icons-material';
import ThemeDark from '../../ThemeDark';
import { buildGraphPalette } from './graphPalette';
import { createRecordingContext } from '../../../utils/tests/recordingCanvasContext';
import { graphLink, graphNode, installPath2DStub } from '../../../utils/tests/graphTestData';
import { type Box, computeLinkCurvatures, linkEndsKey } from './graphGeometry';
import {
  createNodeBoxes,
  levelOfDetail,
  LinkLabel,
  linkDash,
  LOW_CONFIDENCE_THRESHOLD,
  NODE_RADIUS,
  nodeRadius,
  paintGraphLink,
  paintGraphLinkHitArea,
  paintGraphNode,
  paintGraphNodeHitArea,
  paintLinkLabels,
  RELATIONSHIP_NODE_RADIUS,
} from './graphPainting';

const palette = buildGraphPalette(createTheme(ThemeDark() as ThemeOptions));
const fullDetail = levelOfDetail(4, 10);
const plain = { selected: false, preview: false, hovered: false, faded: false, onPath: false };

beforeAll(installPath2DStub);

describe('levelOfDetail', () => {
  it('shows every detail close up', () => {
    expect(levelOfDetail(5, 10)).toEqual({ icons: true, labels: true, secondaryLabels: true, badges: true, arrows: true, linkLabels: true });
  });

  it('keeps a far overview clean', () => {
    expect(levelOfDetail(0.3, 10)).toEqual({ icons: false, labels: false, secondaryLabels: false, badges: false, arrows: false, linkLabels: false });
  });

  it('asks more zoom before labelling a crowded graph', () => {
    expect(levelOfDetail(2, 10).labels).toBe(true);
    expect(levelOfDetail(2, 1000).labels).toBe(false);
  });
});

describe('paintGraphNode', () => {
  it('draws a tinted disc ringed with the entity colour, its icon and its label', () => {
    const ctx = createRecordingContext();
    paintGraphNode(ctx, graphNode(), { palette, globalScale: 4, detail: fullDetail, visual: plain });
    const ring = ctx.callsOf('stroke').find((call) => call.strokeStyle === '#f0b60a');
    expect(ring).toBeDefined();
    const tint = ctx.callsOf('fill').find((call) => call.fillStyle === '#f0b60a' && call.globalAlpha === palette.tintAlpha);
    expect(tint).toBeDefined();
    // The icon of the type, filled as paths in the entity colour.
    expect(ctx.callsOf('fill').filter((call) => call.args[0] !== undefined && call.fillStyle === '#f0b60a').length).toBeGreaterThan(0);
    expect(ctx.texts()).toContain('Emotet');
  });

  it('adds the translated type as a second line close up', () => {
    const ctx = createRecordingContext();
    paintGraphNode(ctx, graphNode(), { palette, globalScale: 5, detail: levelOfDetail(5, 1), visual: plain, typeLabel: 'Malware' });
    expect(ctx.texts()).toEqual(['Emotet', 'Malware']);
  });

  it('cuts a long label with an ellipsis', () => {
    const ctx = createRecordingContext();
    paintGraphNode(ctx, graphNode({ label: 'An intrusion set with an extremely long and descriptive name' }), {
      palette, globalScale: 4, detail: fullDetail, visual: plain,
    });
    expect(ctx.texts()[0].endsWith('\u2026')).toBe(true);
  });

  it('draws the selection halo and the label on an accent pill', () => {
    const ctx = createRecordingContext();
    paintGraphNode(ctx, graphNode(), { palette, globalScale: 4, detail: fullDetail, visual: { ...plain, selected: true } });
    expect(ctx.callsOf('stroke').some((call) => call.strokeStyle === palette.accent)).toBe(true);
    expect(ctx.callsOf('roundRect').length).toBe(1);
    expect(ctx.callsOf('fill').some((call) => call.fillStyle === palette.accent)).toBe(true);
  });

  it('fades a node outside the focus and greys a filtered one', () => {
    const faded = createRecordingContext();
    paintGraphNode(faded, graphNode(), { palette, globalScale: 4, detail: fullDetail, visual: { ...plain, faded: true } });
    expect(faded.callsOf('fillText')[0].globalAlpha).toBe(palette.fadeAlpha);
    const disabled = createRecordingContext();
    paintGraphNode(disabled, graphNode({ disabled: true }), { palette, globalScale: 4, detail: fullDetail, visual: plain });
    expect(disabled.callsOf('stroke').every((call) => call.strokeStyle !== '#f0b60a')).toBe(true);
    expect(disabled.callsOf('fillText')[0].globalAlpha).toBeLessThan(palette.fadeAlpha);
  });

  it('dashes the ring of a nested inferred element in the inferred colour', () => {
    const ctx = createRecordingContext();
    paintGraphNode(ctx, graphNode({ isNestedInferred: true }), { palette, globalScale: 4, detail: fullDetail, visual: plain });
    const ring = ctx.callsOf('stroke').find((call) => call.strokeStyle === palette.inferred);
    expect(ring?.lineDash.length).toBeGreaterThan(0);
  });

  it('draws badges above the node, a dot when the badge has no icon', () => {
    const ctx = createRecordingContext();
    paintGraphNode(ctx, graphNode({ x: 0, y: 0 }), {
      palette,
      globalScale: 4,
      detail: fullDetail,
      visual: plain,
      badges: [
        { key: 'tlp', tone: 'neutral', color: '#2e7d32', label: 'TLP:GREEN' },
        { key: 'confidence', tone: 'warning', icon: SpeedOutlined, label: 'Low confidence', value: 20 },
      ],
    });
    const pills = ctx.callsOf('roundRect');
    expect(pills).toHaveLength(2);
    pills.forEach((pill) => expect(Number(pill.args[1])).toBeLessThan(-NODE_RADIUS));
    expect(ctx.callsOf('fill').some((call) => call.fillStyle === '#2e7d32')).toBe(true);
    expect(ctx.texts()).toContain('20');
  });

  it('hides badges, icons and labels at overview zoom', () => {
    const ctx = createRecordingContext();
    paintGraphNode(ctx, graphNode(), {
      palette,
      globalScale: 0.3,
      detail: levelOfDetail(0.3, 10),
      visual: plain,
      badges: [{ key: 'tlp', tone: 'neutral', label: 'TLP:GREEN' }],
    });
    expect(ctx.texts()).toEqual([]);
    expect(ctx.callsOf('roundRect')).toHaveLength(0);
  });

  it('keeps the label of a hovered node readable even far out', () => {
    const ctx = createRecordingContext();
    paintGraphNode(ctx, graphNode(), { palette, globalScale: 0.3, detail: levelOfDetail(0.3, 10), visual: { ...plain, hovered: true } });
    expect(ctx.texts()).toEqual(['Emotet']);
    expect(Number(/([\d.]+)px/.exec(ctx.callsOf('fillText')[0].font)?.[1]) * 0.3).toBeGreaterThanOrEqual(11.9);
  });

  it('draws relationship nodes smaller than entities', () => {
    expect(nodeRadius(graphNode({ relationship_type: 'uses' }))).toBe(RELATIONSHIP_NODE_RADIUS);
    expect(nodeRadius(graphNode())).toBe(NODE_RADIUS);
  });

  it('skips a node the simulation has not placed yet', () => {
    const ctx = createRecordingContext();
    paintGraphNode(ctx, graphNode({ x: NaN }), { palette, globalScale: 4, detail: fullDetail, visual: plain });
    expect(ctx.calls).toHaveLength(0);
  });

  it('appends the boxes it covers to the buffer it is handed, written in place from frame to frame', () => {
    const covered: Box[] = [];
    const boxes = createNodeBoxes();
    const options = { palette, globalScale: 4, detail: fullDetail, visual: plain };
    expect(paintGraphNode(createRecordingContext(), graphNode({ x: 0 }), options, covered, boxes)).toBe(covered);
    expect(covered).toEqual([boxes.disc, boxes.label]);
    covered.length = 0;
    paintGraphNode(createRecordingContext(), graphNode({ x: 40 }), options, covered, boxes);
    expect(covered[0]).toBe(boxes.disc);
    expect(boxes.disc.x).toBe(40);
    expect(boxes.label.x).toBe(40);
  });
});

describe('paintGraphNodeHitArea', () => {
  it('fills the disc and, when shown, the label', () => {
    const ctx = createRecordingContext();
    paintGraphNodeHitArea(ctx, graphNode(), '#010203', true);
    expect(ctx.callsOf('fill')[0].fillStyle).toBe('#010203');
    expect(ctx.callsOf('fillRect')).toHaveLength(1);
    const noLabel = createRecordingContext();
    paintGraphNodeHitArea(noLabel, graphNode(), '#010203', false);
    expect(noLabel.callsOf('fillRect')).toHaveLength(0);
  });
});

describe('paintGraphLinkHitArea', () => {
  it('paints the hover area of a loop where the loop is drawn, rotated with it', () => {
    const node = graphNode({ id: 'a', x: 0, y: 0 });
    const loop = graphLink(node, node, { id: 'loop' });
    const controls = (rotation: number) => {
      const ctx = createRecordingContext();
      paintGraphLinkHitArea(ctx, loop, '#010203', 4, { curvature: 0.5, rotation });
      const stroke = ctx.callsOf('stroke')[0];
      expect(stroke).toMatchObject({ strokeStyle: '#010203', lineWidth: 6 / 4 + 2 });
      return (ctx.callsOf('bezierCurveTo')[0].args as number[]).slice(0, 4).map((value) => Math.round(value) + 0);
    };
    // Above and right of the node, then above and left of it.
    expect(controls(0)).toEqual([0, -35, 35, 0]);
    expect(controls(-90)).toEqual([-35, 0, 0, -35]);
  });

  it('paints nothing for a link whose ends are not placed yet', () => {
    const ctx = createRecordingContext();
    paintGraphLinkHitArea(ctx, graphLink(graphNode({ id: 'a', x: undefined }), graphNode({ id: 'b' })), '#010203', 4, { curvature: 0, rotation: 0 });
    expect(ctx.callsOf('stroke')).toHaveLength(0);
  });
});

describe('paintGraphLink', () => {
  const a = graphNode({ id: 'a', x: 0, y: 0 });
  const b = graphNode({ id: 'b', x: 100, y: 0 });
  const options = {
    palette,
    globalScale: 4,
    detail: fullDetail,
    visual: { selected: false, hovered: false, faded: false, onPath: false },
    color: palette.link,
    curvature: 0,
    rotation: 0,
  };

  it('runs from ring to ring and ends with an arrowhead', () => {
    const ctx = createRecordingContext();
    const label = paintGraphLink(ctx, graphLink(a, b), options);
    const start = ctx.callsOf('moveTo')[0];
    expect(Number(start.args[0])).toBeGreaterThan(NODE_RADIUS);
    expect(ctx.callsOf('closePath')).toHaveLength(1);
    expect(label).toMatchObject({ text: 'uses', x: 50, y: 0, angle: 0 });
  });

  it('draws a curve for a curved link', () => {
    const ctx = createRecordingContext();
    paintGraphLink(ctx, graphLink(a, b), { ...options, curvature: 0.3 });
    expect(ctx.callsOf('quadraticCurveTo')).toHaveLength(1);
  });

  it('dashes inferred links and dots low-confidence ones', () => {
    expect(linkDash({ inferred: true, isNestedInferred: false })).not.toEqual([]);
    expect(linkDash({ inferred: false, isNestedInferred: false }, LOW_CONFIDENCE_THRESHOLD - 1)).not.toEqual([]);
    expect(linkDash({ inferred: false, isNestedInferred: false }, LOW_CONFIDENCE_THRESHOLD)).toEqual([]);
    const ctx = createRecordingContext();
    paintGraphLink(ctx, graphLink(a, b, { inferred: true }), options);
    expect(ctx.callsOf('stroke')[0].lineDash.length).toBeGreaterThan(0);
  });

  it('highlights a link of the shortest path in the accent colour', () => {
    const ctx = createRecordingContext();
    paintGraphLink(ctx, graphLink(a, b), { ...options, visual: { ...options.visual, onPath: true } });
    expect(ctx.callsOf('stroke')[0].strokeStyle).toBe(palette.accent);
  });

  it('gives no label for a faded or disabled link, nor when labels are out of detail', () => {
    expect(paintGraphLink(createRecordingContext(), graphLink(a, b, { disabled: true }), options)).toBeNull();
    expect(paintGraphLink(createRecordingContext(), graphLink(a, b), { ...options, detail: levelOfDetail(0.5, 10) })).toBeNull();
  });

  it('draws nothing between overlapping nodes or unresolved ends', () => {
    const near = graphNode({ id: 'c', x: 5, y: 0 });
    const ctx = createRecordingContext();
    expect(paintGraphLink(ctx, graphLink(a, near), options)).toBeNull();
    expect(paintGraphLink(ctx, { ...graphLink(a, b), source: 'a', target: 'b' }, options)).toBeNull();
    expect(ctx.calls).toHaveLength(0);
  });
});

describe('paintLinkLabels', () => {
  it('draws the most important labels first and drops those overlapping them', () => {
    const labels: LinkLabel[] = [
      { text: 'uses', x: 0, y: 0, angle: 0, priority: 0, emphasised: false },
      { text: 'targets', x: 1, y: 0, angle: 0, priority: 3, emphasised: true },
      { text: 'indicates', x: 200, y: 0, angle: 0, priority: 0, emphasised: false },
    ];
    const ctx = createRecordingContext();
    paintLinkLabels(ctx, labels, { palette, globalScale: 4 });
    expect(ctx.texts()).toEqual(['targets', 'indicates']);
    expect(ctx.callsOf('strokeText')).toHaveLength(2);
  });

  it('slides a label along its link when the middle covers a node, and leaves it out when no place is free', () => {
    const node = { x: 0, y: 0, halfWidth: 9, halfHeight: 9 };
    const alternatives = [{ x: -40, y: 0, angle: 0 }, { x: 40, y: 0, angle: 0 }];
    const ctx = createRecordingContext();
    paintLinkLabels(ctx, [{ text: 'uses', x: 0, y: 0, angle: 0, priority: 0, emphasised: false, alternatives }], { palette, globalScale: 4, obstacles: [node] });
    expect(ctx.callsOf('translate')[0].args).toEqual([-40, 0]);

    const blocked = createRecordingContext();
    const walls = [node, { ...node, x: -40 }, { ...node, x: 40 }];
    paintLinkLabels(blocked, [{ text: 'uses', x: 0, y: 0, angle: 0, priority: 0, emphasised: false, alternatives }], { palette, globalScale: 4, obstacles: walls });
    expect(blocked.texts()).toEqual([]);
    paintLinkLabels(blocked, [{ text: 'uses', x: 0, y: 0, angle: 0, priority: 3, emphasised: true, alternatives }], { palette, globalScale: 4, obstacles: walls });
    expect(blocked.texts()).toEqual(['uses']);
  });

  it('labels every loop of a group standing for four relationship types, with its count, at the zoom that fits the graph', () => {
    const group = graphNode({ id: 'group:Malware', name: '4 x Malware', label: '4 x Malware', x: 0, y: 0 });
    // Drawn in the order of the relationships, the loops are ordered by id, the relationship type: "downloads" first.
    const types = ['drops', 'variant of', 'related to', 'downloads'];
    const loops = types.map((type) => graphLink(group, group, {
      id: `group|${group.id}|${group.id}|${type.replace(' ', '-')}`,
      label: type,
      represents: type === 'related to' ? 2 : 1,
    }));
    const curvatures = computeLinkCurvatures(loops.map((link) => ({ id: link.id, sourceId: group.id, targetId: group.id })));
    [5.25, 6].forEach((globalScale) => {
      const detail = levelOfDetail(globalScale, 7);
      const obstacles: Box[] = [];
      paintGraphNode(createRecordingContext(), group, { palette, globalScale, detail, visual: plain }, obstacles);
      const labels = loops.map((link) => paintGraphLink(createRecordingContext(), link, {
        palette,
        globalScale,
        detail,
        visual: { selected: false, hovered: false, faded: false, onPath: false },
        color: palette.link,
        ...(curvatures.get(linkEndsKey({ id: link.id, sourceId: group.id, targetId: group.id })) ?? { curvature: 0, rotation: 0 }),
      })).filter((label): label is LinkLabel => !!label);
      const ctx = createRecordingContext();
      paintLinkLabels(ctx, labels, { palette, globalScale, obstacles });
      expect([...ctx.texts()].sort()).toEqual(['downloads', 'drops', 'related to (2)', 'variant of']);
    });
  });

  it('gives every link label two other places along the link, and nodes report what they cover', () => {
    const a = graphNode({ id: 'a', x: 0, y: 0 });
    const b = graphNode({ id: 'b', x: 100, y: 0 });
    const label = paintGraphLink(createRecordingContext(), graphLink(a, b), {
      palette, globalScale: 4, detail: fullDetail, visual: { selected: false, hovered: false, faded: false, onPath: false }, color: palette.link, curvature: 0, rotation: 0,
    });
    expect(label?.alternatives?.map(({ x }) => Math.round(x))).toEqual([expect.any(Number), expect.any(Number)]);
    const [before, after] = label?.alternatives ?? [];
    expect(before.x).toBeLessThan(50);
    expect(after.x).toBeGreaterThan(50);
    const covered = paintGraphNode(createRecordingContext(), graphNode(), { palette, globalScale: 4, detail: fullDetail, visual: plain, badges: [{ key: 'b', tone: 'info', label: 'B' }] });
    expect(covered).toHaveLength(3);
    expect(covered[0]).toMatchObject({ x: graphNode().x, y: graphNode().y });
  });
});
