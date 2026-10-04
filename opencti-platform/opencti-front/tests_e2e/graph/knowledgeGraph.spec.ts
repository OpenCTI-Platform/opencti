import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import GraphPage from '../model/graph.pageModel';
import { createGraphFixture, deleteGraphFixture, GraphFixture, withApiRequest } from '../dataForTesting/graph.data';

/**
 * Non-regression net of the container knowledge graph (Report, and every container sharing the
 * same component): each capability of the graph inventory, driven through the toolbar, the
 * canvas and the details panel.
 */
test.describe('Container knowledge graph', { tag: ['@ce'] }, () => {
  test.describe.configure({ mode: 'serial' });
  let fixture: GraphFixture;

  test.beforeAll(async ({ playwright }) => {
    fixture = await withApiRequest(playwright, (request) => createGraphFixture(request));
  });

  test.afterAll(async ({ playwright }) => {
    await withApiRequest(playwright, (request) => deleteGraphFixture(request, fixture));
  });

  const openGraph = async (graph: GraphPage, page: Page) => {
    await page.goto(`/dashboard/analyses/reports/${fixture.report.id}/knowledge/graph`);
    await graph.waitForGraph(5);
  };

  test('draws every entity and relationship of the container', async ({ page }) => {
    const graph = new GraphPage(page);
    await openGraph(graph, page);
    const state = await graph.snapshot();
    expect(state.nodes.map((n) => n.id).sort()).toEqual([
      fixture.intrusionSet.id, fixture.malware.id, fixture.attackPattern.id, fixture.ipv4.id, fixture.domain.id,
    ].sort());
    expect(state.links.map((l) => l.id).sort()).toEqual(fixture.relationships.map((r) => r.id).sort());
    // Every node is inside the canvas once the graph is fitted.
    const box = await graph.getCanvas().boundingBox();
    for (const node of state.nodes) {
      expect(node.x).toBeGreaterThanOrEqual(0);
      expect(node.y).toBeGreaterThanOrEqual(0);
      expect(node.x).toBeLessThanOrEqual(box?.width ?? 0);
      expect(node.y).toBeLessThanOrEqual(box?.height ?? 0);
    }
  });

  test('switches between 2D and 3D and keeps the choice', async ({ page }) => {
    const graph = new GraphPage(page);
    await openGraph(graph, page);
    await graph.getToolbarButton('Enable 3D mode').click();
    await expect(graph.getToolbarButton('Disable 3D mode')).toBeVisible();
    await expect(page.locator('.force-graph-container')).toHaveCount(0);
    await expect(page.locator('canvas').first()).toBeVisible();
    // 3D disables the 2D-only selection tools.
    await expect(graph.getToolbarButton('Free rectangle select')).toBeDisabled();
    await expect(graph.getToolbarButton('Free select')).toBeDisabled();
    await page.reload();
    await expect(graph.getToolbarButton('Disable 3D mode')).toBeVisible();
    await graph.getToolbarButton('Disable 3D mode').click();
    await graph.waitForGraph(5);
    await expect(graph.getToolbarButton('Enable 3D mode')).toBeVisible();
  });

  test('applies tree layouts, forces, fit and reset of the layout', async ({ page }) => {
    const graph = new GraphPage(page);
    await openGraph(graph, page);
    await graph.getToolbarButton('Enable vertical tree mode').click();
    await expect(graph.getToolbarButton('Disable vertical tree mode')).toBeVisible();
    await graph.waitForGraph(5);
    await graph.getToolbarButton('Disable vertical tree mode').click();
    await expect(graph.getToolbarButton('Enable vertical tree mode')).toBeVisible();

    await graph.getToolbarButton('Enable horizontal tree mode').click();
    await expect(graph.getToolbarButton('Disable horizontal tree mode')).toBeVisible();
    await graph.waitForGraph(5);
    await graph.getToolbarButton('Disable horizontal tree mode').click();
    await expect(graph.getToolbarButton('Enable horizontal tree mode')).toBeVisible();

    // Without forces the tree layouts and the reset are unavailable.
    await graph.getToolbarButton('Disable forces').click();
    await expect(graph.getToolbarButton('Enable vertical tree mode')).toBeDisabled();
    await expect(graph.getToolbarButton('Unfix the nodes and re-apply forces')).toBeDisabled();
    await graph.getToolbarButton('Disable forces').click();
    await expect(graph.getToolbarButton('Enable vertical tree mode')).toBeEnabled();

    await graph.getToolbarButton('Fit graph to canvas').click();
    await graph.getToolbarButton('Unfix the nodes and re-apply forces').click();
    await graph.waitForGraph(5);
    expect(await graph.nodeIds()).toHaveLength(5);
  });

  test('selects nodes with clicks, modifiers, types, search and selection shapes', async ({ page }) => {
    const graph = new GraphPage(page);
    await openGraph(graph, page);
    await graph.arrangeInMiddle([fixture.intrusionSet.id, fixture.malware.id]);
    await graph.waitForGraph(5);

    await graph.clickNode(fixture.intrusionSet.id);
    await expect(graph.getSelectionSummary(1)).toBeVisible();
    await graph.clickNode(fixture.malware.id, ['Control']);
    await expect(graph.getSelectionSummary(2)).toBeVisible();
    await graph.clickBackground();
    await expect(graph.getAnySelectionSummary()).toBeHidden();

    await graph.getToolbarButton('Select all nodes').click();
    await expect(graph.getSelectionSummary(5)).toBeVisible();
    await graph.getToolbarButton('Select Relationships of Selected Nodes').click();
    await expect(graph.getSelectionSummary(9)).toBeVisible();
    await expect(graph.getToolbarButton('Select Child Relationships of Selected Nodes (From)')).toBeVisible();
    await graph.clickBackground();

    await graph.openOptionsAndPick('Select by entity type', 'Malware');
    await expect(graph.getSelectionSummary(1)).toBeVisible();
    await graph.clickBackground();

    await graph.getToolbar().getByPlaceholder('Search these results...').fill(fixture.attackPattern.name);
    await graph.getToolbar().getByPlaceholder('Search these results...').press('Enter');
    await expect(graph.getSelectionSummary(1)).toBeVisible();
    await graph.getToolbar().getByPlaceholder('Search these results...').fill('');
    await graph.clickBackground();

    // The shapes cover the whole drawing: framed first, as the entity without relationships drifts
    // away under the forces once the others were dragged.
    await graph.getControl('Fit the whole graph').click();
    await graph.waitForGraph(5);
    await graph.getToolbarButton('Free rectangle select').click();
    await graph.dragAcrossCanvas();
    await expect(graph.getSelectionSummary(5)).toBeVisible();
    await graph.getToolbarButton('Free rectangle select').click();
    await graph.clickBackground();

    await graph.getToolbarButton('Free select').click();
    await graph.lassoAcrossCanvas();
    await expect(graph.getSelectionSummary(5)).toBeVisible();
    await graph.getToolbarButton('Free select').click();
    await graph.clickBackground();
    await expect(graph.getAnySelectionSummary()).toBeHidden();
  });

  test('filters by entity type, marking, author and time range', async ({ page }) => {
    const graph = new GraphPage(page);
    await openGraph(graph, page);
    const disabledIds = async () => (await graph.snapshot()).nodes.filter((n) => n.disabled).map((n) => n.id).sort();

    await graph.openOptionsAndPick('Filter entity types', 'Malware');
    await expect.poll(disabledIds).toEqual([fixture.malware.id]);
    await graph.getToolbarButton('Clear all filters').click();
    await expect.poll(disabledIds).toEqual([]);

    await graph.openOptionsAndPick('Filter marking definitions', 'TLP:GREEN');
    await expect.poll(disabledIds).toContain(fixture.intrusionSet.id);
    await graph.getToolbarButton('Clear all filters').click();
    await expect.poll(disabledIds).toEqual([]);

    await graph.openOptionsAndPick('Filter authors (created by)', fixture.authorName);
    await expect.poll(disabledIds).toEqual(expect.arrayContaining([fixture.intrusionSet.id, fixture.malware.id]));
    await graph.getToolbarButton('Clear all filters').click();
    await expect.poll(disabledIds).toEqual([]);

    // The filters are kept when the page is opened again.
    await graph.openOptionsAndPick('Filter entity types', 'Malware');
    await page.reload();
    await graph.waitForGraph(5);
    await expect.poll(disabledIds).toEqual([fixture.malware.id]);
    await graph.getToolbarButton('Clear all filters').click();

    await graph.getToolbarButton('Display time range selector').click();
    const handles = page.getByRole('slider');
    await expect(handles).toHaveCount(2);
    // The toolbar grows to show the selector: the handle is measured once it stopped moving.
    const firstHandle = page.locator('.react_time_range__handle_wrapper').first();
    let lastTop = Number.NaN;
    await expect.poll(async () => {
      const top = (await firstHandle.boundingBox())?.y ?? Number.NaN;
      const still = top === lastTop;
      lastTop = top;
      return still;
    }, { intervals: [250] }).toBe(true);
    const rail = await page.locator('.react_time_range__rail__outer').boundingBox();
    const handle = await firstHandle.boundingBox();
    if (!rail || !handle) throw new Error('Time range slider is not rendered');
    await page.mouse.move(handle.x + handle.width / 2, handle.y + handle.height / 2);
    await page.mouse.down();
    await page.mouse.move(rail.x + rail.width * 0.75, handle.y + handle.height / 2, { steps: 10 });
    await page.mouse.up();
    await expect.poll(async () => (await graph.snapshot()).links.filter((l) => l.disabled).length).toBeGreaterThan(0);
    await graph.getToolbarButton('Clear all filters').click();
    await expect.poll(async () => (await graph.snapshot()).links.filter((l) => l.disabled).length).toBe(0);
    await graph.getToolbarButton('Display time range selector').click();
    await expect(handles).toHaveCount(0);
  });

  test('opens the edition, the relationship and the nested relationship creation', async ({ page }) => {
    const graph = new GraphPage(page);
    await openGraph(graph, page);
    await graph.arrangeInMiddle([fixture.domain.id, fixture.ipv4.id]);
    await graph.waitForGraph(5);

    await graph.clickNode(fixture.ipv4.id);
    await expect(graph.getSelectionSummary(1)).toBeVisible();
    await graph.getToolbarButton('Edit the selected item').click();
    await expect(page.getByText('Update an observable', { exact: true })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByText('Update an observable', { exact: true })).toBeHidden();

    // The edition panel resized the page while open: both entities are placed in the middle again,
    // clear of the details panel the selection opens.
    await graph.arrangeInMiddle([fixture.domain.id, fixture.ipv4.id]);
    await graph.waitForGraph(5);
    await graph.clickNode(fixture.domain.id);
    await graph.clickNode(fixture.ipv4.id, ['Shift']);
    await expect(graph.getSelectionSummary(2)).toBeVisible();
    await expect(graph.getToolbarButton('Create a relationship')).toBeEnabled();
    await expect(graph.getToolbarButton('Create a sighting')).toBeEnabled();
    await graph.getToolbarButton('Create a relationship').click();
    await expect(page.getByRole('heading', { name: 'Create a relationship' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('heading', { name: 'Create a relationship' })).toBeHidden();

    // Domain name -> IPv4 address accepts a nested "resolves to" reference.
    await expect(graph.getToolbarButton('Create a nested relationship')).toBeEnabled();
    await graph.getToolbarButton('Create a nested relationship').click();
    await expect(page.getByRole('heading', { name: 'Create a relationship' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('heading', { name: 'Create a relationship' })).toBeHidden();

    // A right-click drag from one node to another opens the relationship creation.
    await graph.clickBackground();
    await graph.rightDragBetween(fixture.domain.id, fixture.ipv4.id);
    await expect(page.getByRole('heading', { name: 'Create a relationship' })).toBeVisible();
    await page.keyboard.press('Escape');
  });

  test('keeps a dragged position after a reload', async ({ page }) => {
    const graph = new GraphPage(page);
    await openGraph(graph, page);
    await graph.dragNode(fixture.malware.id, 90, 70);
    await graph.waitForGraph(5);
    const before = await graph.node(fixture.malware.id);
    await page.reload();
    await graph.waitForGraph(5);
    const after = await graph.node(fixture.malware.id);
    expect(Math.abs(after.gx - before.gx)).toBeLessThan(2);
    expect(Math.abs(after.gy - before.gy)).toBeLessThan(2);
  });

  test('exports the graph area as an image', async ({ page }) => {
    const graph = new GraphPage(page);
    await openGraph(graph, page);
    await page.getByRole('button', { name: 'Export to image' }).click();
    const download = page.waitForEvent('download');
    await page.getByRole('menuitem', { name: /with background/ }).first().click();
    expect((await download).suggestedFilename()).toMatch(/\.png$/);
  });

  test('adds entities from the toolbar and removes the selection after confirmation', async ({ page }) => {
    const graph = new GraphPage(page);
    await openGraph(graph, page);
    await page.getByRole('button', { name: 'Add an entity to this container' }).click();
    await expect(page.getByText('Add entities', { exact: true })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByText('Add entities', { exact: true })).toBeHidden();

    await graph.arrangeInMiddle([fixture.attackPattern.id]);
    await graph.waitForGraph(5);
    await graph.clickNode(fixture.attackPattern.id);
    await expect(graph.getSelectionSummary(1)).toBeVisible();
    await graph.getToolbarButton('Remove selected items').click();
    await expect(page.getByText('Do you want to remove these elements?')).toBeVisible();
    await page.getByRole('button', { name: 'Cancel' }).click();
    expect(await graph.nodeIds()).toContain(fixture.attackPattern.id);

    await graph.getToolbarButton('Remove selected items').click();
    await page.getByRole('button', { name: 'Remove' }).click();
    await expect.poll(() => graph.nodeIds()).not.toContain(fixture.attackPattern.id);
  });
});
