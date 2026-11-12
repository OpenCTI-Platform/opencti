import { expect, test } from '../fixtures/baseFixtures';
import GraphPage from '../model/graph.pageModel';
import { createGraphFixture, deleteGraphFixture, GraphFixture, withApiRequest } from '../dataForTesting/graph.data';

/**
 * Non-regression net of the two read-mostly graph surfaces: the container correlation graph and
 * the graph view of the "Analyses" tab of an entity.
 */
test.describe('Correlation and analyses graphs', { tag: ['@ce'] }, () => {
  test.describe.configure({ mode: 'serial' });
  let fixture: GraphFixture;

  test.beforeAll(async ({ playwright }) => {
    fixture = await withApiRequest(playwright, (request) => createGraphFixture(request));
  });

  test.afterAll(async ({ playwright }) => {
    await withApiRequest(playwright, (request) => deleteGraphFixture(request, fixture));
  });

  test('links shared observables to the other containers, then every shared entity', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/analyses/reports/${fixture.report.id}/knowledge/correlation`);
    await graph.waitForGraph(3);
    // Observables and indicators only, by default.
    await expect.poll(async () => (await graph.nodeIds()).sort()).toEqual(
      [fixture.ipv4.id, fixture.report.id, fixture.correlatedReport.id].sort(),
    );
    await expect(graph.getToolbarButton('Show only correlated observables and indicators')).toBeVisible();

    await graph.getToolbarButton('Show all correlated entities').click();
    await expect.poll(() => graph.nodeIds()).toContain(fixture.malware.id);
    const state = await graph.snapshot();
    expect(state.links.filter((l) => l.sourceId === fixture.malware.id).map((l) => l.targetId).sort())
      .toEqual([fixture.report.id, fixture.correlatedReport.id].sort());

    await graph.getToolbarButton('Show only correlated observables and indicators').click();
    await expect.poll(() => graph.nodeIds()).not.toContain(fixture.malware.id);

    await graph.runToolbarAction('Select all nodes');
    await expect(graph.getSelectionSummary(3)).toBeVisible();
    await graph.clickBackground();
    await graph.getToolbar().getByPlaceholder('Search these results...').fill(fixture.correlatedReport.name);
    await graph.getToolbar().getByPlaceholder('Search these results...').press('Enter');
    await expect(graph.getSelectionSummary(1)).toBeVisible();
  });

  test('draws the containers of an entity in the graph view of its analyses', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/arsenal/malwares/${fixture.malware.id}/analyses`);
    await page.getByRole('button', { name: 'graph' }).click();
    await graph.waitForGraph(2);
    await expect.poll(() => graph.nodeIds()).toEqual(expect.arrayContaining([fixture.report.id, fixture.correlatedReport.id]));
    await expect(page.getByText(/Limitations applied, number of fully loaded containers/).first()).toBeVisible();
    // Read-only surface: no search and no content edition in the graph toolbar (the page above
    // the graph has a search field of its own).
    await expect(graph.getToolbar().getByPlaceholder('Search these results...')).toHaveCount(0);
    await expect(graph.getToolbarButton('Remove selected items')).toHaveCount(0);
    await graph.runToolbarAction('Select all nodes');
    await expect(graph.getAnySelectionSummary()).toBeVisible();
  });
});
