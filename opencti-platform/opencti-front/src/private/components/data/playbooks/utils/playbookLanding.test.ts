import { describe, expect, it } from 'vitest';
import type { Node } from 'reactflow';
import { PLAYBOOK_LANDING, playbookFitZoom, playbookLandingViewport } from './playbookLanding';
import { PLAYBOOK_CARD } from '../types/nodes/playbookNodeGeometry';

const step = (id: string, x: number, y: number, entry = false): Node => ({
  id,
  type: 'workflow',
  position: { x, y },
  data: { component: { is_entry_point: entry } },
});
const PANE = { width: 1440, height: 700 };
// An 11-step pipeline, 3 columns wide and 7 ranks deep: its fit lands far under a readable zoom.
const TALL = [
  step('entry', 400, 0, true),
  ...Array.from({ length: 10 }, (_, i) => step(`s${i}`, (i % 3) * 320, 208 * (1 + Math.floor(i / 2)))),
];

describe('playbookLanding', () => {
  it('keeps the fit when the cards stay readable', () => {
    const small = [step('entry', 0, 0, true), step('b', 0, 208), step('c', 320, 208)];
    expect(playbookFitZoom(small, PANE)).toBeGreaterThanOrEqual(PLAYBOOK_LANDING.minZoom);
    expect(playbookLandingViewport(small, PANE, 'vertical')).toBeNull();
  });

  it('lands a large playbook at the readable zoom on its entry point, top centre in the vertical layout', () => {
    expect(playbookFitZoom(TALL, PANE)).toBeLessThan(PLAYBOOK_LANDING.minZoom);
    const viewport = playbookLandingViewport(TALL, PANE, 'vertical')!;
    expect(viewport.zoom).toBe(PLAYBOOK_LANDING.minZoom);
    // the entry card is centred across the pane, its top a margin under the pane top
    const left = 400 * viewport.zoom + viewport.x;
    expect(Math.abs(left + (PLAYBOOK_CARD.width * viewport.zoom) / 2 - PANE.width / 2)).toBeLessThanOrEqual(1);
    expect(viewport.y).toBe(PLAYBOOK_LANDING.margin);
    expect(Number.isInteger(viewport.x) && Number.isInteger(viewport.y)).toBe(true);
  });

  it('lands on the left edge, centred down the pane, in the horizontal layout', () => {
    const wide = TALL.map((n) => ({ ...n, position: { x: n.position.y * 1.5, y: n.position.x / 2 } }));
    const viewport = playbookLandingViewport(wide, { width: 900, height: 700 }, 'horizontal')!;
    expect(viewport.zoom).toBe(PLAYBOOK_LANDING.minZoom);
    expect(viewport.x).toBe(PLAYBOOK_LANDING.margin);
    const top = 200 * viewport.zoom + viewport.y;
    expect(Math.abs(top + (PLAYBOOK_CARD.height * viewport.zoom) / 2 - 350)).toBeLessThanOrEqual(1);
  });

  it('ignores the add buttons and lands nowhere for an empty playbook', () => {
    expect(playbookLandingViewport([], PANE, 'vertical')).toBeNull();
    expect(playbookLandingViewport([{ id: 'p', type: 'placeholder', position: { x: 0, y: 0 }, data: {} }], PANE, 'vertical')).toBeNull();
  });
});
