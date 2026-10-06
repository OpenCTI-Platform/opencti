import { afterEach, describe, expect, it } from 'vitest';
import { createTheme, ThemeOptions } from '@mui/material/styles';
import ThemeDark from '../../ThemeDark';
import ThemeLight from '../../ThemeLight';
import { buildGraphPalette, dataColorOutline } from './graphPalette';
import { collisionForce } from './collisionForce';
import { isOverlayOpen, shortcutOf } from './useGraphKeyboardShortcuts';
import { graphStateToLocalStorage, normalizeGraphStateParams } from './graphUtils';
import { readLegendOpen, writeLegendOpen } from './graphLegendPreference';
import { readHiddenNodeIds, writeHiddenNodeIds } from './graphHiddenNodes';
import { graphNodeTitle } from './useGraphParser';
import { graphNode } from '../../../utils/tests/graphTestData';
import { glyphFromMarkup } from './graphIcons';
import type { GraphState } from '../graph.types';

describe('collisionForce', () => {
  it('pushes two overlapping nodes apart and leaves distant ones alone', () => {
    const nodes = [{ x: 0, y: 0 }, { x: 5, y: 0 }, { x: 500, y: 500 }].map((n) => ({ ...n, vx: 0, vy: 0 }));
    const force = collisionForce(20);
    force.initialize(nodes);
    force(1);
    expect(nodes[0].vx).toBeLessThan(0);
    expect(nodes[1].vx).toBeGreaterThan(0);
    expect(nodes[2].vx).toBe(0);
  });

  it('never moves a fixed node and separates nodes on the same spot', () => {
    const fixed = { x: 0, y: 0, fx: 0, fy: 0, vx: 0, vy: 0 };
    const free = { x: 0, y: 0, vx: 0, vy: 0 };
    const force = collisionForce(20);
    force.initialize([fixed, free]);
    force(1);
    expect(fixed.vx).toBe(0);
    expect(Math.hypot(free.vx, free.vy)).toBeGreaterThan(0);
  });
});

describe('shortcutOf', () => {
  const key = (k: string, extra: Partial<KeyboardEvent> = {}) => ({ key: k, shiftKey: false, ctrlKey: false, metaKey: false, altKey: false, ...extra });

  it('maps the keys of the shortcut list', () => {
    expect(shortcutOf(key('f'))).toBe('fit');
    expect(shortcutOf(key('F', { shiftKey: true }))).toBe('fitSelection');
    expect(shortcutOf(key('a', { ctrlKey: true }))).toBe('selectAll');
    expect(shortcutOf(key('a', { metaKey: true }))).toBe('selectAll');
    expect(shortcutOf(key('Escape'))).toBe('clearSelection');
    expect(shortcutOf(key('ContextMenu'))).toBe('openContextMenu');
    expect(shortcutOf(key('F10', { shiftKey: true }))).toBe('openContextMenu');
    expect(shortcutOf(key('F10'))).toBeNull();
    expect(shortcutOf(key('?', { shiftKey: true }))).toBe('showShortcuts');
    expect(shortcutOf(key('H', { shiftKey: true }))).toBe('showHidden');
  });

  it('ignores other keys and browser combinations', () => {
    expect(shortcutOf(key('x'))).toBeNull();
    expect(shortcutOf(key('f', { ctrlKey: true }))).toBeNull();
    expect(shortcutOf(key('f', { altKey: true }))).toBeNull();
  });
});

describe('graphNodeTitle', () => {
  type Raw = NonNullable<ReturnType<typeof graphNode>['raw']>;

  it('gives the full name of an entity as plain text, whatever it contains', () => {
    const raw = { id: 'x', entity_type: 'Intrusion-Set', name: 'Tools & <Techniques> of a very long named group' } as unknown as Raw;
    expect(graphNodeTitle(graphNode({ label: 'Tools & <Techniques>...', name: 'Tools &amp; &lt;Techniques&gt;\n2025', raw }))).toBe('Tools & <Techniques> of a very long named group');
  });

  it('keeps the label of relationship nodes, groups and nodes without their object', () => {
    expect(graphNodeTitle(graphNode({ label: 'Uses', relationship_type: 'uses', raw: { id: 'r' } as unknown as Raw }))).toBe('Uses');
    expect(graphNodeTitle(graphNode({ label: '3 Malware', groupOf: { entityType: 'Malware', memberIds: ['a', 'b', 'c'] } }))).toBe('3 Malware');
    expect(graphNodeTitle(graphNode({ label: 'Emotet', raw: undefined }))).toBe('Emotet');
  });
});

describe('isOverlayOpen', () => {
  const page = (html: string) => {
    const root = document.createElement('div');
    root.innerHTML = html;
    return root;
  };

  it('ignores the overlays kept mounted while closed', () => {
    expect(isOverlayOpen(page('<div class="MuiDialog-root MuiModal-root MuiModal-hidden" aria-hidden="true"><div role="dialog" aria-modal="true"></div></div>'))).toBe(false);
    expect(isOverlayOpen(page('<div class="MuiDrawer-modal MuiModal-hidden"></div><ul role="menu" hidden></ul>'))).toBe(false);
    expect(isOverlayOpen(page('<div role="dialog"></div>'))).toBe(false);
  });

  it('counts an open dialog, drawer, popover or menu', () => {
    expect(isOverlayOpen(page('<div class="MuiDialog-root MuiModal-root"><div role="dialog" aria-modal="true"></div></div>'))).toBe(true);
    expect(isOverlayOpen(page('<div class="MuiPopover-root"></div>'))).toBe(true);
    expect(isOverlayOpen(page('<ul role="menu"></ul>'))).toBe(true);
  });
});

describe('graph view state persistence', () => {
  it('saves the new view options next to the existing ones', () => {
    const saved = graphStateToLocalStorage({
      mode3D: false,
      modeTree: null,
      withForces: true,
      disabledEntityTypes: [],
      disabledCreators: [],
      disabledMarkings: [],
      layoutMode: 'radial',
      layoutCentreId: 'node-1',
      hiddenNodeIds: ['node-2'],
      collapsedEntityTypes: ['Malware'],
      disabledRelationshipTypes: ['uses'],
      showLegend: false,
      highlightedPath: { nodeIds: ['a', 'b'], linkKeys: ['ab|a|b'] },
    } as unknown as GraphState);
    expect(saved).toMatchObject({
      layoutMode: 'radial',
      layoutCentreId: 'node-1',
      collapsedEntityTypes: ['Malware'],
      disabledRelationshipTypes: ['uses'],
    });
    expect(saved).not.toHaveProperty('highlightedPath');
    expect(saved).not.toHaveProperty('showLegend');
    // Saved apart, in local storage only: the list is unbounded, a URL is not.
    expect(saved).not.toHaveProperty('hiddenNodeIds');
  });

  it('reads them back from the strings of the URL, leaving the legend state to the user preference', () => {
    expect(normalizeGraphStateParams({
      hiddenNodeIds: 'a,b',
      collapsedEntityTypes: '',
      showLegend: 'false',
      layoutMode: 'unknown',
      layoutCentreId: '',
    })).toEqual({ collapsedEntityTypes: [], layoutMode: null, layoutCentreId: null });
    expect(normalizeGraphStateParams({ layoutMode: 'tiers', showLegend: true })).toEqual({ layoutMode: 'tiers' });
  });
});

describe('hidden entities storage', () => {
  afterEach(() => window.localStorage.clear());

  it('keeps the hidden entities of each graph apart, out of the URL', () => {
    const ids = Array.from({ length: 2000 }, (_, index) => `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`);
    writeHiddenNodeIds('view-graph-a', ids);
    expect(readHiddenNodeIds('view-graph-a')).toEqual(ids);
    expect(readHiddenNodeIds('view-graph-b')).toEqual([]);
    writeHiddenNodeIds('view-graph-a', []);
    expect(window.localStorage.getItem('view-graph-a-hidden-nodes')).toBeNull();
  });

  it('reads nothing hidden from an unreadable entry', () => {
    window.localStorage.setItem('view-graph-a-hidden-nodes', '{not json');
    expect(readHiddenNodeIds('view-graph-a')).toEqual([]);
    window.localStorage.setItem('view-graph-a-hidden-nodes', '{"a":1}');
    expect(readHiddenNodeIds('view-graph-a')).toEqual([]);
  });
});

describe('legend preference', () => {
  afterEach(() => window.localStorage.clear());

  it('opens the legend until the user minimizes it, for every graph of that user only', () => {
    expect(readLegendOpen('user-1')).toBe(true);
    writeLegendOpen('user-1', false);
    expect(readLegendOpen('user-1')).toBe(false);
    expect(readLegendOpen('user-2')).toBe(true);
    writeLegendOpen('user-1', true);
    expect(readLegendOpen('user-1')).toBe(true);
  });
});

describe('buildGraphPalette', () => {
  it('takes every colour from the theme, dark or light', () => {
    const dark = createTheme(ThemeDark() as ThemeOptions);
    const light = createTheme(ThemeLight() as ThemeOptions);
    const darkPalette = buildGraphPalette(dark);
    const lightPalette = buildGraphPalette(light);
    expect(darkPalette.mode).toBe('dark');
    expect(lightPalette.mode).toBe('light');
    expect(darkPalette.background).toBe(dark.palette.background.default);
    expect(lightPalette.background).toBe(light.palette.background.default);
    expect(lightPalette.accent).toBe(light.palette.secondary.main);
    expect(lightPalette.tones.warning).toBe(light.palette.warning.main);
    // Read against the surface behind, so the tint is lighter on a light surface.
    expect(lightPalette.tintAlpha).toBeLessThan(darkPalette.tintAlpha);
  });

  it('outlines a colour of the data as light as the surface, such as the white of TLP:CLEAR', () => {
    const surfaces = { surface: '#ffffff', textSecondary: '#5f6b7a' };
    expect(dataColorOutline('#ffffff', surfaces)).toBe('#5f6b7a');
    expect(dataColorOutline('#fafafa', surfaces)).toBe('#5f6b7a');
    expect(dataColorOutline('#2e7d32', surfaces)).toBeNull();
    expect(dataColorOutline('#ffffff', { surface: '#0f1724', textSecondary: '#9aa5b1' })).toBeNull();
    expect(dataColorOutline('not a colour', surfaces)).toBeNull();
  });
});

describe('glyphFromMarkup', () => {
  it('reads the paths and circles of an icon', () => {
    const glyph = glyphFromMarkup('<svg viewBox="0 0 24 24"><path d="M1 1h2"></path><circle cx="12" cy="12" r="3"></circle><path></path></svg>');
    expect(glyph.shapes).toEqual([{ kind: 'path', d: 'M1 1h2' }, { kind: 'circle', cx: 12, cy: 12, r: 3 }]);
  });
});
