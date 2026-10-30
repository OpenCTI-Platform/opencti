import { expect, type Locator, Page } from '@playwright/test';

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
  const propsKey = Object.keys(host).find((key) => key.startsWith('__reactProps$'));
  type Fiber = {
    memoizedProps?: { graphData?: { nodes: Record<string, unknown>[]; links: Record<string, unknown>[] } };
    return?: Fiber;
    alternate?: Fiber;
  };
  let fiber = (fiberKey ? host[fiberKey] : undefined) as Fiber | undefined;
  // React keeps two versions of every fiber and the element may point to the stale one: the
  // current one is the version holding the props last committed to the element.
  if (fiber?.alternate && propsKey && fiber.memoizedProps !== host[propsKey]) fiber = fiber.alternate;
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
    return this.page.locator('[data-graph-toolbar]').last();
  }

  /** The one toolbar of the graph, as assistive technologies see it. */
  getToolbarRegion() {
    return this.page.getByRole('toolbar', { name: 'Graph toolbar' });
  }

  /** The "More actions" menu closing the toolbar, opened. */
  async openMoreActions() {
    const menu = this.page.getByRole('menu', { name: 'More actions' });
    if (!(await menu.isVisible())) await this.getToolbarButton('More actions').click();
    await expect(menu).toBeVisible();
    return menu;
  }

  async closeMoreActions() {
    const menus = this.page.getByRole('menu');
    for (let attempt = 0; attempt < 3 && (await menus.count()) > 0; attempt += 1) {
      await this.page.keyboard.press('Escape');
    }
    await expect(menus).toHaveCount(0);
  }

  /** An item of a menu by its label, which a count or the reason it is disabled may follow. */
  private static menuItem(menu: Locator, name: string, exact = false) {
    const label = exact ? name : new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`);
    return menu.getByRole('menuitem', { name: label }).or(menu.getByRole('menuitemcheckbox', { name: label }));
  }

  /**
   * Whether an action sits in the toolbar itself; otherwise "More actions" (what the toolbar has no
   * room for) or the context menu of the graph (the rare actions) lists it. The toolbar is waited for
   * first: it renders again when the graph switches between 2D and 3D.
   */
  async isInToolbar(name: string) {
    await expect(this.getToolbarButton('Fit the whole graph')).toBeVisible();
    return (await this.getToolbarButton(name).count()) > 0;
  }

  /** The context menu of the graph, opened by a right click on a node or, without one, on the empty canvas. */
  async openContextMenu(nodeId?: string) {
    let spot: [number, number] | null = null;
    if (nodeId) {
      const { x, y } = await this.pagePoint(nodeId);
      await this.page.mouse.move(x - 30, y - 30);
      spot = [x, y];
    } else {
      await expect.poll(async () => {
        spot = await this.freeSpot();
        return spot !== null;
      }, { message: 'No free spot on the canvas to right-click', timeout: 15000 }).toBe(true);
    }
    const [x, y] = spot as unknown as [number, number];
    // The menu is the one of what the pointer is on: the hover settles on the next frame.
    await this.page.mouse.move(x, y, { steps: 6 });
    await this.page.waitForTimeout(150);
    await this.page.mouse.click(x, y, { button: 'right' });
    const menu = this.page.getByRole('menu', { name: 'Graph actions' });
    await expect(menu).toBeVisible();
    return menu;
  }

  /** The menu listing an action the toolbar has no button for: "More actions" when it lists it, else the context menu. */
  private async openMenuListing(name: string) {
    if ((await this.getToolbarButton('More actions').count()) > 0) {
      const menu = await this.openMoreActions();
      if ((await GraphPage.menuItem(menu, name).count()) > 0) return menu;
      await this.closeMoreActions();
    }
    return this.openContextMenu();
  }

  /** Runs an action of the toolbar, from the toolbar, from "More actions" or from the context menu, wherever it is. */
  async runToolbarAction(name: string) {
    if (await this.isInToolbar(name)) {
      await this.getToolbarButton(name).click();
      return;
    }
    const menu = await this.openMenuListing(name);
    await GraphPage.menuItem(menu, name).click();
  }

  /** Checks that a toggle of the toolbar is on or off, wherever it is. */
  async expectToolbarToggle(name: string, on: boolean) {
    if (await this.isInToolbar(name)) {
      await expect(this.getToolbarButton(name)).toHaveAttribute('aria-pressed', String(on));
      return;
    }
    const menu = await this.openMenuListing(name);
    await expect(GraphPage.menuItem(menu, name)).toHaveAttribute('aria-checked', String(on));
    await this.closeMoreActions();
  }

  /** Checks that an action of the toolbar can run or not, wherever it is. */
  async expectToolbarActionEnabled(name: string, enabled: boolean) {
    if (await this.isInToolbar(name)) {
      const button = this.getToolbarButton(name);
      if (enabled) await expect(button).toBeEnabled();
      else await expect(button).toBeDisabled();
      return;
    }
    const menu = await this.openMenuListing(name);
    const item = GraphPage.menuItem(menu, name);
    if (enabled) await expect(item).not.toHaveAttribute('aria-disabled', 'true');
    else await expect(item).toHaveAttribute('aria-disabled', 'true');
    await this.closeMoreActions();
  }

  async hoverNode(id: string) {
    const { x, y } = await this.pagePoint(id);
    await this.page.mouse.move(x - 30, y - 30);
    await this.page.mouse.move(x, y, { steps: 6 });
  }

  /** A button of the graph toolbar; other buttons of the page may carry the same name. */
  getToolbarButton(name: string | RegExp) {
    return this.getToolbar().getByRole('button', { name, exact: typeof name === 'string' });
  }

  getSelectionSummary(count: number) {
    return this.page.getByText(count === 1 ? '1 object selected' : `${count} objects selected`, { exact: true });
  }

  getAnySelectionSummary() {
    return this.page.getByText(/^\d+ objects? selected$/);
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
    // Still over two intervals in a row: longer than the delay of the first framing of a graph.
    let previous = '';
    let stillFor = 0;
    await expect.poll(async () => {
      const state = await this.page.evaluate(readGraphSnapshot);
      const current = JSON.stringify(state?.nodes.map(({ x, y }) => [Math.round(x), Math.round(y)]));
      stillFor = current === previous ? stillFor + 1 : 0;
      previous = current;
      return stillFor >= 2;
    }, { timeout: 60000, intervals: [700] }).toBe(true);
  }

  /**
   * Waits for at least `minNodes` nodes and `minLinks` links and for their layout to stand still, in
   * graph units so that the framing animation does not count; returns the time (`Date.now()`) of the
   * first sample of the still layout, to measure how long loading and laying it out took.
   */
  async waitForStableLayout(minNodes: number, minLinks = 0): Promise<number> {
    await expect(this.getCanvas()).toBeVisible();
    let previous = { at: 0, positions: '' };
    let stableAt = 0;
    await expect.poll(async () => {
      const state = await this.page.evaluate(readGraphSnapshot);
      const at = Date.now();
      if (!state || state.nodes.length < minNodes || state.links.length < minLinks) return false;
      const positions = JSON.stringify(state.nodes.map(({ gx, gy }) => [Math.round(gx), Math.round(gy)]));
      if (positions === previous.positions) {
        stableAt = previous.at;
        return true;
      }
      previous = { at, positions };
      return false;
    }, { timeout: 120000, intervals: [250] }).toBe(true);
    return stableAt;
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
    // Framed first: the forces may have moved a node under a panel since the graph was last fitted,
    // where a drag would grab the panel instead.
    await this.getToolbarButton('Fit the whole graph').click();
    await this.waitForGraph(ids.length);
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
    // The hover card of the node clicked before may cover this one: it closes once the pointer leaves it.
    const card = this.page.getByRole('group', { name: 'Details on hover' });
    if (await card.isVisible()) {
      const box = await this.getCanvas().boundingBox();
      if (box) await this.page.mouse.move(box.x + box.width / 2, box.y + 5);
      await expect(card).toBeHidden();
    }
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
    // The gesture picks the nodes the pointer moves over: a first move on the source, as a hand
    // does, whatever the zoom; the same on the target before the release.
    await this.page.mouse.move(from.x + 1, from.y + 1);
    await this.page.mouse.move((from.x + to.x) / 2, (from.y + to.y) / 2, { steps: 8 });
    await this.page.mouse.move(to.x, to.y, { steps: 8 });
    await this.page.mouse.move(to.x + 1, to.y + 1);
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

  /** An empty spot of the canvas, far from every node and under nothing floating over it. */
  private async freeSpot(): Promise<[number, number] | null> {
    const box = await this.getCanvas().boundingBox();
    if (!box) throw new Error('Canvas has no bounding box');
    const state = await this.snapshot();
    const candidates: [number, number][] = [];
    for (let fy = 0.05; fy < 0.95; fy += 0.1) {
      for (let fx = 0.05; fx < 0.95; fx += 0.1) candidates.push([box.width * fx, box.height * fy]);
    }
    const farFromNodes = candidates.filter(([cx, cy]) => state.nodes.every((n) => Math.hypot(n.x - cx, n.y - cy) > 60));
    const onPage = farFromNodes.map(([cx, cy]): [number, number] => [box.x + cx, box.y + cy]);
    return this.page.evaluate((points) => points.find(([x, y]) => {
      const element = document.elementFromPoint(x, y);
      return element?.tagName === 'CANVAS';
    }) ?? null, onPage);
  }

  /**
   * Clicks an empty spot of the canvas: far from every node and not under anything floating over
   * the canvas (panels, cards, the details panel), waiting for a closing dialog or drawer to leave.
   */
  async clickBackground() {
    let spot: [number, number] | null = null;
    await expect.poll(async () => {
      spot = await this.freeSpot();
      return spot !== null;
    }, { message: 'No free spot on the canvas to click', timeout: 15000 }).toBe(true);
    const [x, y] = spot as unknown as [number, number];
    await this.page.mouse.click(x, y);
  }

  /**
   * Picks one entry of a toolbar list (select by type, filters), from the toolbar or from its
   * submenu in "More actions" or in the context menu, then closes the list.
   */
  async openOptionsAndPick(actionName: string, option: string) {
    if (!(await this.isInToolbar(actionName))) {
      const menu = await this.openMenuListing(actionName);
      await GraphPage.menuItem(menu, actionName).click();
      await expect(this.page.getByRole('menu')).toHaveCount(2);
      // The pointer would travel from the submenu trigger to the item across the parent menu,
      // which closes the submenu on its way: the item is picked from the keyboard.
      const item = GraphPage.menuItem(this.page.getByRole('menu').last(), option, true).first();
      await item.focus();
      await item.press('Enter');
      await this.closeMoreActions();
      return;
    }
    await this.getToolbarButton(actionName).click();
    const list = this.page.getByRole('menu', { name: actionName });
    await GraphPage.menuItem(list, option, true).first().click();
    // A single-choice list closes itself on pick; a multiple-choice one stays open.
    await this.page.waitForTimeout(300);
    if (await list.isVisible()) await this.page.keyboard.press('Escape');
    await expect(this.page.getByRole('menu')).toHaveCount(0);
  }
}
