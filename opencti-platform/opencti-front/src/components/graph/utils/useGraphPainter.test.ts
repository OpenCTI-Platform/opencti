import { describe, expect, it } from 'vitest';
import { createTheme, ThemeOptions } from '@mui/material/styles';
import useGraphPainter, { isHoveredLink, linkHoverTarget } from './useGraphPainter';
import { testRenderHook } from '../../../utils/tests/test-render';
import { createRecordingContext } from '../../../utils/tests/recordingCanvasContext';
import ThemeDark from '../../ThemeDark';
import type { GraphLink, GraphNode } from '../graph.types';
import { registerGraphBadgeProvider } from '../badges';

const theme = createTheme(ThemeDark() as ThemeOptions);

const node = (overrides: Partial<GraphNode> = {}): GraphNode => ({
  id: 'node-1',
  name: 'Emotet\n2025-01-01',
  label: 'Emotet',
  disabled: false,
  defaultDate: new Date('2025-01-01T00:00:00.000Z'),
  entity_type: 'Malware',
  parent_types: ['Stix-Domain-Object', 'Stix-Core-Object'],
  relationship_type: '',
  isNestedInferred: false,
  createdBy: { id: 'author', name: 'Author' },
  markedBy: [],
  val: 1,
  color: '#f0b60a',
  x: 10,
  y: 20,
  z: 0,
  isObservable: false,
  rawImg: '',
  img: {} as HTMLImageElement,
  ...overrides,
});

const link = (overrides: Partial<GraphLink> = {}): GraphLink => ({
  id: 'link-1',
  name: 'uses',
  label: 'uses',
  disabled: false,
  defaultDate: new Date('2025-01-01T00:00:00.000Z'),
  entity_type: 'uses',
  parent_types: ['basic-relationship', 'stix-core-relationship'],
  relationship_type: 'uses',
  isNestedInferred: false,
  createdBy: { id: 'author', name: 'Author' },
  markedBy: [],
  source: node({ id: 'a', x: 0, y: 0 }),
  source_id: 'a',
  target: node({ id: 'b', x: 100, y: 0 }),
  target_id: 'b',
  inferred: false,
  ...overrides,
});

describe('link hover targets', () => {
  it('tells apart the two connectors of a nested relationship, which share its id', () => {
    const toNested = link({ id: 'nested', target: node({ id: 'nested' }), target_id: 'nested' });
    const fromNested = link({ id: 'nested', source: 'nested', source_id: 'nested', target: 'b' } as Partial<GraphLink>);
    const hovered = linkHoverTarget(fromNested);
    expect(hovered).toEqual({ kind: 'link', id: 'nested', sourceId: 'nested', targetId: 'b' });
    expect(isHoveredLink(hovered, linkHoverTarget(fromNested))).toBe(true);
    expect(isHoveredLink(hovered, linkHoverTarget(toNested))).toBe(false);
    // A target known by its id alone designates every link of that id.
    expect(isHoveredLink({ kind: 'link', id: 'nested' }, linkHoverTarget(toNested))).toBe(true);
    expect(isHoveredLink({ kind: 'node', id: 'nested' }, linkHoverTarget(toNested))).toBe(false);
  });
});

describe('useGraphPainter', () => {
  describe('linkColorPaint', () => {
    it('uses the primary colour for a regular link', () => {
      const { hook } = testRenderHook(() => useGraphPainter());
      expect(hook.result.current.linkColorPaint(link())).toBe(theme.palette.primary.main);
    });

    it('uses the selection colour for a selected link', () => {
      const selected = link();
      const { hook } = testRenderHook(() => useGraphPainter({
        selectedLinks: [selected], selectedNodes: [], detailsPreviewSelected: undefined, search: undefined,
      }));
      expect(hook.result.current.linkColorPaint(selected)).toBe(theme.palette.secondary.main);
    });

    it('uses the warning colour for inferred and nested-inferred links', () => {
      const { hook } = testRenderHook(() => useGraphPainter());
      expect(hook.result.current.linkColorPaint(link({ inferred: true }))).toBe(theme.palette.warning.main);
      expect(hook.result.current.linkColorPaint(link({ isNestedInferred: true }))).toBe(theme.palette.warning.main);
    });

    it('greys out disabled links and links outside an active search', () => {
      const { hook } = testRenderHook(() => useGraphPainter());
      expect(hook.result.current.linkColorPaint(link({ disabled: true }))).toBe(theme.palette.background.paper);
      const { hook: searching } = testRenderHook(() => useGraphPainter({
        selectedLinks: [], selectedNodes: [], detailsPreviewSelected: undefined, search: 'emo',
      }));
      expect(searching.result.current.linkColorPaint(link())).toBe(theme.palette.background.paper);
    });

    it('marks a selected node in 3D with the selection accent, its sphere and its label', () => {
      const chosen = { id: 'chosen', color: '#123456', disabled: false } as GraphNode;
      const other = { id: 'other', color: '#654321', disabled: false } as GraphNode;
      const faded = { id: 'faded', color: '#654321', disabled: true } as GraphNode;
      const { hook } = testRenderHook(() => useGraphPainter({
        selectedLinks: [], selectedNodes: [chosen], detailsPreviewSelected: undefined, search: undefined,
      }));
      const painter = hook.result.current;
      expect(painter.nodeThreeColor(chosen)).toBe(theme.palette.secondary.main);
      expect(painter.nodeThreeLabelColor(chosen)).toBe(theme.palette.secondary.main);
      expect(painter.nodeThreeColor(other)).toBe('#654321');
      expect(painter.nodeThreeLabelColor(other)).not.toBe(theme.palette.secondary.main);
      expect(painter.nodeThreeColor(faded)).toBe(painter.nodeThreeLabelColor(faded));
    });

    it('colours the relationship itself for the image export, whatever is selected or searched', () => {
      const selected = link();
      const { hook } = testRenderHook(() => useGraphPainter({
        selectedLinks: [selected], selectedNodes: [], detailsPreviewSelected: undefined, search: 'emo',
      }));
      expect(hook.result.current.linkBaseColor(selected)).toBe(theme.palette.primary.main);
      expect(hook.result.current.linkBaseColor(link())).toBe(theme.palette.primary.main);
      expect(hook.result.current.linkBaseColor(link({ inferred: true }))).toBe(theme.palette.warning.main);
      expect(hook.result.current.linkBaseColor(link({ disabled: true }))).toBe(theme.palette.background.paper);
    });
  });

  describe('nodePaint', () => {
    it('draws the label of the node', () => {
      const { hook } = testRenderHook(() => useGraphPainter());
      const ctx = createRecordingContext();
      hook.result.current.nodePaint(node(), ctx);
      expect(ctx.texts()).toContain('Emotet');
    });

    it('shows the number of elements not displayed yet when asked to', () => {
      const { hook } = testRenderHook(() => useGraphPainter());
      const counts: [number | undefined, string][] = [[5, '5+'], [150, '99+'], [undefined, '?']];
      counts.forEach(([numberOfConnectedElement, expected]) => {
        const ctx = createRecordingContext();
        hook.result.current.nodePaint(node({ numberOfConnectedElement }), ctx, undefined, true);
        expect(ctx.texts()).toContain(expected);
      });
    });

    it('draws at most three badges, the most severe first, and counts the others', () => {
      const removals = (['info', 'info', 'error', 'info'] as const).map((tone, index) => registerGraphBadgeProvider({
        id: `test-badge-${index}`,
        order: 900 + index,
        badgesFor: () => [{ key: `test-badge-${index}`, tone, label: `badge ${index}`, value: `v${index}` }],
      }));
      try {
        const { hook } = testRenderHook(() => useGraphPainter());
        const ctx = createRecordingContext();
        hook.result.current.nodePaint(node(), ctx, 4);
        const texts = ctx.texts();
        expect(texts).toEqual(expect.arrayContaining(['v2', 'v0', 'v1', '+1']));
        expect(texts).not.toContain('v3');
      } finally {
        removals.forEach((remove) => remove());
      }
    });

    it('draws a restricted entity with a dashed outline', () => {
      const { hook } = testRenderHook(() => useGraphPainter());
      const ctx = createRecordingContext();
      hook.result.current.nodePaint(node({ isRestricted: true, label: 'Restricted' }), ctx);
      const outline = ctx.callsOf('stroke')[0];
      expect(outline.lineDash.length).toBeGreaterThan(0);
      expect(ctx.texts()).toContain('Restricted');
    });

    it('draws no counter when every connected element is already displayed', () => {
      const { hook } = testRenderHook(() => useGraphPainter());
      const ctx = createRecordingContext();
      hook.result.current.nodePaint(node({ numberOfConnectedElement: 0 }), ctx, undefined, true);
      expect(ctx.texts()).toContain('Emotet');
      expect(ctx.texts().filter((text) => /\+$/.test(text) || text === '?')).toEqual([]);
    });

    it('fades the nodes outside the selection', () => {
      const selected = node({ id: 'selected' });
      const { hook } = testRenderHook(() => useGraphPainter({
        selectedLinks: [], selectedNodes: [selected], detailsPreviewSelected: undefined, search: undefined,
      }));
      const ctx = createRecordingContext();
      hook.result.current.nodePaint(node({ id: 'other' }), ctx);
      const faded = ctx.callsOf('fillText').find((call) => call.args[0] === 'Emotet');
      expect(faded?.globalAlpha).toBeLessThan(1);
      const ctxSelected = createRecordingContext();
      hook.result.current.nodePaint(selected, ctxSelected);
      const full = ctxSelected.callsOf('fillText').find((call) => call.args[0] === 'Emotet');
      expect(full?.globalAlpha).toBe(1);
    });
  });

  describe('nodePointerAreaPaint', () => {
    it('fills the hit area of the node with the colour it is given', () => {
      const { hook } = testRenderHook(() => useGraphPainter());
      const ctx = createRecordingContext();
      hook.result.current.nodePointerAreaPaint(node(), '#123456', ctx);
      const arc = ctx.callsOf('arc')[0];
      expect(arc.args.slice(0, 2)).toEqual([10, 20]);
      expect(ctx.callsOf('fill')[0].fillStyle).toBe('#123456');
    });
  });

  describe('linkThreeLabelPosition', () => {
    it('places the 3D label in the middle of the link', () => {
      const { hook } = testRenderHook(() => useGraphPainter());
      const sprite = { position: { x: 0, y: 0, z: 0 } };
      hook.result.current.linkThreeLabelPosition?.(
        sprite as never,
        { start: { x: 0, y: 0, z: 0 }, end: { x: 10, y: 20, z: 30 } },
        link() as never,
      );
      expect(sprite.position).toEqual({ x: 5, y: 10, z: 15 });
    });
  });
});
