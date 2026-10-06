import { expect, test } from '../fixtures/baseFixtures';
import GraphPage from '../model/graph.pageModel';
import { createGraphFixture, deleteGraphFixture, GraphFixture, withApiRequest } from '../dataForTesting/graph.data';

/**
 * Non-regression net of the investigation graph: the shared capabilities plus what only the
 * investigation offers (expansion with counts, rollback, double-click expansion, adding entities).
 */
test.describe('Investigation graph', { tag: ['@ce'] }, () => {
  test.describe.configure({ mode: 'serial' });
  let fixture: GraphFixture;

  test.beforeAll(async ({ playwright }) => {
    fixture = await withApiRequest(playwright, (request) => createGraphFixture(request));
  });

  test.afterAll(async ({ playwright }) => {
    await withApiRequest(playwright, (request) => deleteGraphFixture(request, fixture));
  });

  test('draws the investigated entities and the relationships between them', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/workspaces/investigations/${fixture.investigation.id}`);
    await graph.waitForGraph(3);
    const state = await graph.snapshot();
    expect(state.nodes.map((n) => n.id)).toEqual(expect.arrayContaining([
      fixture.intrusionSet.id, fixture.malware.id, fixture.attackPattern.id,
    ]));
    await expect(page.getByRole('button', { name: 'Add an entity to this investigation' })).toBeVisible();
  });

  test('expands a selected entity and rolls the expansion back', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/workspaces/investigations/${fixture.investigation.id}`);
    await graph.waitForGraph(3);
    const initialCount = (await graph.nodeIds()).length;

    await expect(graph.getToolbarButton('Expand the selected entities')).toBeDisabled();
    await graph.arrangeInMiddle([fixture.malware.id]);
    await graph.waitForGraph(3);
    await graph.clickNode(fixture.malware.id);
    await expect(graph.getSelectionSummary(1)).toBeVisible();
    await graph.getToolbarButton('Expand the selected entities').click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    // Nothing is ticked when the dialog opens, and expanding without a type does nothing.
    await dialog.getByRole('checkbox', { name: /^IPv4 address/ }).click();
    await dialog.getByRole('button', { name: 'Expand' }).click();
    await expect(dialog).toBeHidden();
    await expect.poll(() => graph.nodeIds()).toContain(fixture.ipv4.id);
    expect((await graph.nodeIds()).length).toBeGreaterThan(initialCount);

    await graph.getToolbarButton('Restore the state of the graphic before the last expansion').click();
    const rollbackDialog = page.getByRole('dialog', { name: /Revert to Pre-Expansion State/ });
    await expect(rollbackDialog).toBeVisible();
    await rollbackDialog.getByRole('button', { name: 'Validate' }).click();
    await expect(rollbackDialog).toBeHidden();
    await expect.poll(async () => (await graph.nodeIds()).length).toBe(initialCount);
    expect(await graph.nodeIds()).not.toContain(fixture.ipv4.id);
  });

  test('opens the expansion with a double click on a node', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/workspaces/investigations/${fixture.investigation.id}`);
    await graph.waitForGraph(3);
    await graph.arrangeInMiddle([fixture.intrusionSet.id]);
    await graph.waitForGraph(3);
    await graph.doubleClickNode(fixture.intrusionSet.id);
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
  });

  test('keeps selection, filters and layout tools available', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/workspaces/investigations/${fixture.investigation.id}`);
    await graph.waitForGraph(3);
    await graph.runToolbarAction('Select all nodes');
    await expect(graph.getAnySelectionSummary()).toBeVisible();
    await graph.clickBackground();
    await graph.openOptionsAndPick('Filter by type', 'Malware');
    await expect.poll(async () => (await graph.snapshot()).nodes.filter((n) => n.disabled).map((n) => n.id)).toEqual([fixture.malware.id]);
    await graph.runToolbarAction('Clear all filters');
    await graph.runToolbarAction('Hierarchical layout (left to right)');
    await graph.expectToolbarToggle('Hierarchical layout (left to right)', true);
    await graph.runToolbarAction('Hierarchical layout (left to right)');
    await graph.getToolbar().getByPlaceholder('Search these results...').fill(fixture.malware.name);
    await graph.getToolbar().getByPlaceholder('Search these results...').press('Enter');
    await expect(graph.getSelectionSummary(1)).toBeVisible();
  });

  test('exports the investigation as an image', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/workspaces/investigations/${fixture.investigation.id}`);
    await graph.waitForGraph(3);
    await page.getByRole('button', { name: 'Export to image' }).click();
    const download = page.waitForEvent('download');
    await page.getByRole('menuitem', { name: /with background/ }).first().click();
    expect((await download).suggestedFilename()).toMatch(/\.png$/);
  });
});
