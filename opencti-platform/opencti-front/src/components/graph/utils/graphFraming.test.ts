import { describe, expect, it } from 'vitest';
import { frameBox, measureGraphPanels, ScreenRect } from './graphFraming';

const size = { width: 1000, height: 600 };
const options = { padding: 20, maxZoom: 6 };
/** Where a graph point lands on the canvas for a frame. */
const onScreen = (frame: { k: number; x: number; y: number }, point: { x: number; y: number }) => ({
  x: size.width / 2 + (point.x - frame.x) * frame.k,
  y: size.height / 2 + (point.y - frame.y) * frame.k,
});
const inside = (point: { x: number; y: number }, rect: ScreenRect) => point.x > rect.left && point.x < rect.right && point.y > rect.top && point.y < rect.bottom;

describe('frameBox', () => {
  it('centres and fits the box when nothing floats over the canvas', () => {
    const frame = frameBox({ x: [-100, 100], y: [-50, 50] }, size, [], options);
    expect(frame.x).toBeCloseTo(0);
    expect(frame.y).toBeCloseTo(0);
    expect(frame.k).toBeCloseTo((size.width - 40) / 200);
  });

  it('never zooms past the maximum, for a single node', () => {
    expect(frameBox({ x: [10, 10], y: [5, 5] }, size, [], options)).toEqual({ k: 6, x: 10, y: 5 });
  });

  it('keeps a wide graph above a low legend on the bottom left', () => {
    const legend = { left: 12, top: 400, right: 260, bottom: 588 };
    const box = { x: [-300, 300] as [number, number], y: [-20, 20] as [number, number] };
    const frame = frameBox(box, size, [legend], options);
    [{ x: -300, y: 20 }, { x: -300, y: -20 }, { x: 300, y: 20 }].forEach((corner) => {
      expect(inside(onScreen(frame, corner), legend)).toBe(false);
    });
    const leftmost = onScreen(frame, { x: -300, y: 20 });
    expect(leftmost.x).toBeLessThan(legend.right);
    expect(leftmost.y).toBeLessThan(legend.top);
  });

  it('keeps a tall graph beside the panels and clear of a details panel on the right', () => {
    const controls = { left: 12, top: 12, right: 52, bottom: 160 };
    const details = { left: 760, top: 0, right: 1000, bottom: 600 };
    const box = { x: [-40, 40] as [number, number], y: [-300, 300] as [number, number] };
    const frame = frameBox(box, size, [controls, details], options);
    const left = onScreen(frame, { x: -40, y: -300 });
    const right = onScreen(frame, { x: 40, y: 300 });
    expect(left.x).toBeGreaterThan(controls.right);
    expect(right.x).toBeLessThan(details.left);
  });

  it('ignores panels outside the canvas or without area', () => {
    const panels = [{ left: 1200, top: 0, right: 1300, bottom: 100 }, { left: 10, top: 10, right: 10, bottom: 10 }];
    expect(frameBox({ x: [-100, 100], y: [-50, 50] }, size, panels, options)).toEqual(frameBox({ x: [-100, 100], y: [-50, 50] }, size, [], options));
  });

  it('frames a single node above the full-width toolbar, never beside it, off the canvas', () => {
    const toolbar = { left: 0, top: 520, right: 1000, bottom: 600 };
    const frame = frameBox({ x: [10, 10], y: [5, 5] }, size, [toolbar], { padding: 200, maxZoom: 6 });
    const node = onScreen(frame, { x: 10, y: 5 });
    expect(node.x).toBeCloseTo(size.width / 2);
    expect(node.y).toBeLessThan(toolbar.top);
  });

  it('keeps a column of nodes beside a full-height details panel and above the full-width toolbar', () => {
    const details = { left: 760, top: 0, right: 1000, bottom: 600 };
    const toolbar = { left: 0, top: 520, right: 1000, bottom: 600 };
    const frame = frameBox({ x: [0, 0], y: [-100, 100] }, size, [details, toolbar], options);
    [{ x: 0, y: -100 }, { x: 0, y: 100 }].forEach((end) => {
      const point = onScreen(frame, end);
      expect(point.x).toBeGreaterThan(0);
      expect(point.x).toBeLessThan(details.left);
      expect(point.y).toBeGreaterThan(0);
      expect(point.y).toBeLessThan(toolbar.top);
    });
  });

  it('leaves out a panel that covers the whole canvas', () => {
    const box = { x: [-100, 100] as [number, number], y: [-50, 50] as [number, number] };
    expect(frameBox(box, size, [{ left: 0, top: 0, right: 1000, bottom: 600 }], options)).toEqual(frameBox(box, size, [], options));
  });
});

describe('measureGraphPanels', () => {
  it('measures the floating panels relative to the canvas', () => {
    const viewport = document.createElement('div');
    viewport.innerHTML = '<canvas></canvas><div data-graph-panel></div><div class="MuiDrawer-paperAnchorRight"></div><div></div>';
    const rect = (left: number, top: number, width: number, height: number) => () => ({
      left, top, right: left + width, bottom: top + height, width, height, x: left, y: top, toJSON: () => ({}),
    }) as DOMRect;
    const canvas = viewport.querySelector('canvas') as HTMLCanvasElement;
    canvas.getBoundingClientRect = rect(100, 50, 1000, 600);
    const [panel, drawer] = Array.from(viewport.querySelectorAll<HTMLElement>('[data-graph-panel], .MuiDrawer-paperAnchorRight'));
    panel.getBoundingClientRect = rect(112, 62, 40, 150);
    drawer.getBoundingClientRect = rect(860, 50, 240, 600);
    expect(measureGraphPanels(viewport, canvas)).toEqual([
      { left: 12, top: 12, right: 52, bottom: 162 },
      { left: 760, top: 0, right: 1000, bottom: 600 },
    ]);
    // The toolbar docked under the graph lives elsewhere in the page and covers the bottom of the canvas.
    const toolbar = document.createElement('div');
    toolbar.getBoundingClientRect = rect(100, 570, 1000, 80);
    expect(measureGraphPanels(viewport, canvas, [toolbar, null])).toHaveLength(3);
    expect(measureGraphPanels(viewport, canvas, [toolbar])[2]).toEqual({ left: 0, top: 520, right: 1000, bottom: 600 });
  });

  it('frames the nodes above a toolbar covering the bottom of the canvas', () => {
    const toolbar: ScreenRect = { left: 0, top: 520, right: 1000, bottom: 600 };
    const frame = frameBox({ x: [-100, 100], y: [-100, 100] }, { width: 1000, height: 600 }, [toolbar], { padding: 0, maxZoom: 10 });
    // 512 free pixels (the 80 covered and a gap of 8) for 200 graph units, the centre moved by half of them.
    expect(frame.k).toBeCloseTo(2.56);
    expect(frame.y).toBeCloseTo(44 / 2.56);
  });
});
