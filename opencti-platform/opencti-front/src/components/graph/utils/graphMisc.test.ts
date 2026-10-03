import { describe, expect, it } from 'vitest';
import { createTheme, ThemeOptions } from '@mui/material/styles';
import ThemeDark from '../../ThemeDark';
import ThemeLight from '../../ThemeLight';
import { buildGraphPalette } from './graphPalette';
import { collisionForce } from './collisionForce';
import { shortcutOf } from './useGraphKeyboardShortcuts';
import { graphStateToLocalStorage, normalizeGraphStateParams } from './graphUtils';
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
    expect(shortcutOf(key('?', { shiftKey: true }))).toBe('showShortcuts');
    expect(shortcutOf(key('H', { shiftKey: true }))).toBe('showHidden');
  });

  it('ignores other keys and browser combinations', () => {
    expect(shortcutOf(key('x'))).toBeNull();
    expect(shortcutOf(key('f', { ctrlKey: true }))).toBeNull();
    expect(shortcutOf(key('f', { altKey: true }))).toBeNull();
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
      highlightedPath: { nodeIds: ['a', 'b'], linkIds: ['ab'] },
    } as GraphState);
    expect(saved).toMatchObject({
      layoutMode: 'radial',
      layoutCentreId: 'node-1',
      hiddenNodeIds: ['node-2'],
      collapsedEntityTypes: ['Malware'],
      disabledRelationshipTypes: ['uses'],
      showLegend: false,
    });
    expect(saved).not.toHaveProperty('highlightedPath');
  });

  it('reads them back from the strings of the URL', () => {
    expect(normalizeGraphStateParams({
      hiddenNodeIds: 'a,b',
      collapsedEntityTypes: '',
      showLegend: 'false',
      layoutMode: 'unknown',
      layoutCentreId: '',
    })).toEqual({ hiddenNodeIds: ['a', 'b'], collapsedEntityTypes: [], showLegend: false, layoutMode: null, layoutCentreId: null });
    expect(normalizeGraphStateParams({ layoutMode: 'tiers', showLegend: true })).toEqual({ layoutMode: 'tiers', showLegend: true });
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
});

describe('glyphFromMarkup', () => {
  it('reads the paths and circles of an icon', () => {
    const glyph = glyphFromMarkup('<svg viewBox="0 0 24 24"><path d="M1 1h2"></path><circle cx="12" cy="12" r="3"></circle><path></path></svg>');
    expect(glyph.shapes).toEqual([{ kind: 'path', d: 'M1 1h2' }, { kind: 'circle', cx: 12, cy: 12, r: 3 }]);
  });
});
