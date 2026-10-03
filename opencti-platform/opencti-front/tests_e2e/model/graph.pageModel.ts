import { expect, Page } from '@playwright/test';

export interface GraphNodeOnScreen {
  id: string;
  entityType: string;
  disabled: boolean;
  /** Canvas coordinates, in CSS pixels, of the node centre. */
  x: number;
  y: number;
  /** Graph coordinates, independent of the zoom. */
  gx: number;
  gy: number;
}

export interface GraphLinkState {
  id: string;
  sourceId: string;
  targetId: string;
  disabled: boolean;
}

interface GraphSnapshot {
  nodes: GraphNodeOnScreen[];
  links: GraphLinkState[];
  zoom: number;
}

/**
 * Reads what the 2D canvas draws, straight from the props handed to the rendering library: the
 * canvas exposes no DOM per node, and these props are the only source that holds the settled
 * positions. The zoom transform is the one d3-zoom stores on the canvas element.
 *
 * Runs in the browser, so it must stay self-contained.
 */
const readGraphSnapshot = (): GraphSnapshot | null => {
  const container = document.querySelector('.force-graph-container');
  const canvas = container?.querySelector('canvas') as (HTMLCanvasElement & { __zoom?: { k: number; x: number; y: number } }) | null;
  const host = container?.parentElement as (HTMLElement & Record<string, unknown>) | null | undefined;
  if (!canvas || !host) return null;
  const fiberKey = Object.keys(host).find((key) => key.startsWith('__reactFiber$'));
  type Fiber = { memoizedProps?: { graphData?: { nodes: Record<string, unknown>[]; links: Record<string, unknown>[] } }; return?: Fiber };
  let fiber = (fiberKey ? host[fiberKey] : undefined) as Fiber | undefined;
  while (fiber && !fiber.memoizedProps?.graphData) fiber = fiber.return;
  const graphData = fiber?.memoizedProps?.graphData;
  if (!graphData) return null;
  const transform = canvas.__zoom ?? { k: 1, x: 0, y: 0 };
  const endpointId = (end: unknown) => (typeof end === 'object' && end !== null ? String((end as { id: string }).id) : String(end));
  return {
    zoom: transform.k,
    nodes: graphData.nodes.map((node) => ({
      id: String(node.id),
      entityType: String(node.entity_type ?? ''),
      disabled: Boolean(node.disabled),
      x: Number(node.x ?? 0) * transform.k + transform.x,
      y: Number(node.y ?? 0) * transform.k + transform.y,
      gx: Number(node.x ?? 0),
      gy: Number(node.y ?? 0),
    })),
    links: graphData.links.map((link) => ({
      id: String(link.id),
      sourceId: endpointId(link.source),
      targetId: endpointId(link.target),
      disabled: Boolean(link.disabled),
    })),
  };
};

export default class GraphPage {
  constructor(private page: Page) {}

  getCanvas() {
    return this.page.locator('.force-graph-container canvas').first();
  }

  /** The toolbar docked at the bottom of every graph. */
  getToolbar() {
    return this.page.locator('.MuiDrawer-paperAnchorDockedBottom').last();
  }

  getToolbarButton(name: string | RegExp) {
    return this.page.getByRole('button', { name, exact: typeof name === 'string' });
  }

  getSelectionSummary(count: number) {
    return this.page.getByText(`${count} objects selected`, { exact: true });
  }

  getAnySelectionSummary() {
    return this.page.getByText(/^\d+ objects selected$/);
  }

  async snapshot(): Promise<GraphSnapshot> {
    const state = await this.page.evaluate(readGraphSnapshot);
    if (!state) throw new Error('The 2D graph is not rendered');
    return state;
  }

  /**
   * Waits until the canvas holds at least `minNodes` nodes and the layout stopped moving, so that
   * a later click lands where the node is drawn.
   */
  async waitForGraph(minNodes: number) {
    await expect(this.getCanvas()).toBeVisible();
    await expect.poll(async () => {
      const state = await this.page.evaluate(readGraphSnapshot);
      return state?.nodes.length ?? 0;
    }, { timeout: 60000 }).toBeGreaterThanOrEqual(minNodes);
    let previous = '';
    await expect.poll(async () => {
      const state = await this.page.evaluate(readGraphSnapshot);
      const current = JSON.stringify(state?.nodes.map(({ x, y }) => [Math.round(x), Math.round(y)]));
      const settled = current === previous;
      previous = current;
      return settled;
    }, { timeout: 60000, intervals: [700] }).toBe(true);
  }

  async node(id: string) {
    const state = await this.snapshot();
    const found = state.nodes.find((n) => n.id === id);
    if (!found) throw new Error(`Node ${id} is not in the graph`);
    return found;
  }

  async nodeIds() {
    const state = await this.snapshot();
    return state.nodes.map((n) => n.id);
  }

  async pagePoint(id: string) {
    const box = await this.getCanvas().boundingBox();
    if (!box) throw new Error('Canvas has no bounding box');
    const { x, y } = await this.node(id);
    return { x: box.x + x, y: box.y + y };
  }

  /**
   * Places the given nodes side by side in the middle of the canvas, one drag each, so a click or
   * a drag between them never lands under the details panel that opens on the right.
   */
  async arrangeInMiddle(ids: string[]) {
    const box = await this.getCanvas().boundingBox();
    if (!box) throw new Error('Canvas has no bounding box');
    for (let index = 0; index < ids.length; index += 1) {
      const target = { x: box.width * (0.25 + (0.3 * index) / Math.max(1, ids.length - 1)), y: box.height * 0.5 };
      const current = await this.node(ids[index]);
      await this.dragNode(ids[index], target.x - current.x, target.y - current.y);
    }
    await this.clickBackground();
  }

  async clickNode(id: string, modifiers: ('Shift' | 'Control' | 'Alt')[] = []) {
    const { x, y } = await this.pagePoint(id);
    for (const key of modifiers) await this.page.keyboard.down(key);
    await this.page.mouse.click(x, y);
    for (const key of modifiers) await this.page.keyboard.up(key);
  }

  async doubleClickNode(id: string) {
    const { x, y } = await this.pagePoint(id);
    await this.page.mouse.dblclick(x, y);
  }

  async dragNode(id: string, dx: number, dy: number) {
    const { x, y } = await this.pagePoint(id);
    await this.page.mouse.move(x, y);
    await this.page.mouse.down();
    await this.page.mouse.move(x + dx / 2, y + dy / 2, { steps: 5 });
    await this.page.mouse.move(x + dx, y + dy, { steps: 5 });
    await this.page.mouse.up();
  }

  async rightDragBetween(fromId: string, toId: string) {
    const from = await this.pagePoint(fromId);
    const to = await this.pagePoint(toId);
    await this.page.mouse.move(from.x, from.y);
    await this.page.mouse.down({ button: 'right' });
    await this.page.mouse.move((from.x + to.x) / 2, (from.y + to.y) / 2, { steps: 8 });
    await this.page.mouse.move(to.x, to.y, { steps: 8 });
    await this.page.mouse.up({ button: 'right' });
  }

  /**
   * Left edge of the gestures covering the whole drawing: clear of the panels floating over the
   * left of the canvas, and still left of every node once the graph is fitted.
   */
  private static readonly GESTURE_LEFT = 70;

  /** Drags a selection shape over the whole drawing, from one corner to the opposite one. */
  async dragAcrossCanvas() {
    const box = await this.getCanvas().boundingBox();
    if (!box) throw new Error('Canvas has no bounding box');
    await this.page.mouse.move(box.x + GraphPage.GESTURE_LEFT, box.y + 5);
    await this.page.mouse.down();
    await this.page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 5 });
    await this.page.mouse.move(box.x + box.width - 5, box.y + box.height - 5, { steps: 5 });
    await this.page.mouse.up();
  }

  /** Draws a closed loop around the whole drawing, the lasso selection gesture. */
  async lassoAcrossCanvas() {
    const box = await this.getCanvas().boundingBox();
    if (!box) throw new Error('Canvas has no bounding box');
    const left = box.x + GraphPage.GESTURE_LEFT;
    const points = [
      [left, box.y + 5],
      [box.x + box.width - 5, box.y + 5],
      [box.x + box.width - 5, box.y + box.height - 5],
      [left, box.y + box.height - 5],
      [left, box.y + 8],
    ];
    await this.page.mouse.move(points[0][0], points[0][1]);
    await this.page.mouse.down();
    for (const [x, y] of points.slice(1)) {
      await this.page.mouse.move(x, y, { steps: 10 });
    }
    await this.page.mouse.up();
  }

  /**
   * Clicks an empty spot of the canvas: far from every node and not under anything floating over
   * the canvas (panels, cards, the details panel).
   */
  async clickBackground() {
    const box = await this.getCanvas().boundingBox();
    if (!box) throw new Error('Canvas has no bounding box');
    const state = await this.snapshot();
    const candidates: [number, number][] = [];
    for (let fy = 0.05; fy < 0.95; fy += 0.1) {
      for (let fx = 0.05; fx < 0.95; fx += 0.1) candidates.push([box.width * fx, box.height * fy]);
    }
    const farFromNodes = candidates.filter(([cx, cy]) => state.nodes.every((n) => Math.hypot(n.x - cx, n.y - cy) > 60));
    const onCanvas = await this.page.evaluate((points) => points.find(([x, y]) => {
      const element = document.elementFromPoint(x, y);
      return element?.tagName === 'CANVAS';
    }) ?? null, farFromNodes.map(([cx, cy]) => [box.x + cx, box.y + cy]));
    if (!onCanvas) throw new Error('No free spot on the canvas to click');
    await this.page.mouse.click(onCanvas[0], onCanvas[1]);
  }

  /** Picks one entry of a toolbar option list (select by type, filters), then closes the list. */
  async openOptionsAndPick(buttonName: string, option: string) {
    await this.getToolbarButton(buttonName).click();
    const list = this.page.getByRole('presentation').last();
    await list.getByRole('button', { name: option }).first().click();
    // A single-choice list closes itself on pick; a multiple-choice one stays open.
    await this.page.waitForTimeout(300);
    if (await list.isVisible()) await this.page.keyboard.press('Escape');
    await expect(this.page.locator('.MuiPopover-root')).toHaveCount(0);
  }
}
