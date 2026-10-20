/** A rectangle in screen pixels, relative to the top left corner of the canvas. */
export interface ScreenRect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

/** Bounds of the nodes to frame, in graph units, as the rendering library gives them. */
export interface GraphBox {
  x: [number, number];
  y: [number, number];
}

export interface FrameInsets {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

export interface Frame {
  /** Zoom level. */
  k: number;
  /** Graph point to show at the centre of the canvas. */
  x: number;
  y: number;
}

const NO_INSETS: FrameInsets = { left: 0, top: 0, right: 0, bottom: 0 };
const GAP = 8;

/**
 * Height of the toolbar docked under the graph, closed and with the time range selector open: the
 * selector grows the toolbar over the bottom of the canvas.
 */
export const GRAPH_TOOLBAR_HEIGHT = 54;
export const GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE = 134;

/** Floating panels over the canvas: view controls, legend, details panel. */
export const GRAPH_PANEL_SELECTOR = '[data-graph-panel], .MuiDrawer-paperAnchorRight';

/** A panel is cleared by keeping the nodes beside it or by keeping them above or below it. */
const clearancesOf = (panel: ScreenRect, size: { width: number; height: number }): Partial<FrameInsets>[] => {
  const nearLeft = (panel.left + panel.right) / 2 < size.width / 2;
  const nearTop = (panel.top + panel.bottom) / 2 < size.height / 2;
  return [
    nearLeft ? { left: panel.right + GAP } : { right: size.width - panel.left + GAP },
    nearTop ? { top: panel.bottom + GAP } : { bottom: size.height - panel.top + GAP },
  ];
};

const merge = (insets: FrameInsets, extra: Partial<FrameInsets>): FrameInsets => ({
  left: Math.max(insets.left, extra.left ?? 0),
  top: Math.max(insets.top, extra.top ?? 0),
  right: Math.max(insets.right, extra.right ?? 0),
  bottom: Math.max(insets.bottom, extra.bottom ?? 0),
});

/** False for insets consuming a whole axis, such as clearing the full-width toolbar by its side. */
const leavesRoom = (insets: FrameInsets, size: { width: number; height: number }) => (
  size.width - insets.left - insets.right > 0 && size.height - insets.top - insets.bottom > 0
);

const frameWithin = (box: GraphBox, size: { width: number; height: number }, insets: FrameInsets, padding: number, maxZoom: number): Frame => {
  const width = Math.max(1, size.width - insets.left - insets.right - 2 * padding);
  const height = Math.max(1, size.height - insets.top - insets.bottom - 2 * padding);
  const boxWidth = Math.max(box.x[1] - box.x[0], 1e-6);
  const boxHeight = Math.max(box.y[1] - box.y[0], 1e-6);
  const k = Math.min(width / boxWidth, height / boxHeight, maxZoom);
  // The free area is off-centre when the insets differ: the canvas centre shows the graph point
  // that much away from the centre of the box.
  const shiftX = (insets.left - insets.right) / 2;
  const shiftY = (insets.top - insets.bottom) / 2;
  return {
    k,
    x: (box.x[0] + box.x[1]) / 2 - shiftX / k,
    y: (box.y[0] + box.y[1]) / 2 - shiftY / k,
  };
};

/**
 * The zoom and centre that show the whole box clear of every floating panel. Each panel can be
 * cleared on its side or above / below it; the combination giving the largest zoom wins, so a
 * wide graph goes above a low legend and a tall one beside it. A combination leaving no room on
 * an axis is never a choice, and a panel no combination can clear is left out.
 */
export const frameBox = (
  box: GraphBox,
  size: { width: number; height: number },
  panels: readonly ScreenRect[],
  options: { padding: number; maxZoom: number },
): Frame => {
  const visible = panels.filter((p) => p.right > p.left && p.bottom > p.top && p.right > 0 && p.bottom > 0 && p.left < size.width && p.top < size.height);
  const combinations = visible.reduce<FrameInsets[]>(
    (all, panel) => {
      const cleared = all
        .flatMap((insets) => clearancesOf(panel, size).map((clearance) => merge(insets, clearance)))
        .filter((insets) => leavesRoom(insets, size));
      return cleared.length > 0 ? cleared : all;
    },
    [NO_INSETS],
  );
  return combinations
    .map((insets) => frameWithin(box, size, insets, options.padding, options.maxZoom))
    .reduce((best, frame) => (frame.k > best.k ? frame : best));
};

/**
 * The panels floating over a canvas, relative to it, and the `outside` elements covering it from
 * elsewhere in the page (the toolbar docked under the graph).
 */
export const measureGraphPanels = (viewport: HTMLElement, canvas: HTMLCanvasElement, outside: readonly (HTMLElement | null)[] = []): ScreenRect[] => {
  const origin = canvas.getBoundingClientRect();
  const panels = [...Array.from(viewport.querySelectorAll<HTMLElement>(GRAPH_PANEL_SELECTOR)), ...outside.filter((element): element is HTMLElement => !!element)];
  return panels.map((panel) => {
    const rect = panel.getBoundingClientRect();
    return { left: rect.left - origin.left, top: rect.top - origin.top, right: rect.right - origin.left, bottom: rect.bottom - origin.top };
  });
};
