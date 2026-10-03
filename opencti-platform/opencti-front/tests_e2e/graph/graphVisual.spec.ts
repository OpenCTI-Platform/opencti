import fs from 'node:fs';
import { Locator, Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import GraphPage from '../model/graph.pageModel';
import { createGraphFixture, deleteGraphFixture, GraphFixture, withApiRequest } from '../dataForTesting/graph.data';

/**
 * Visual regression of the graph surfaces, on constant data and deterministic layouts so that
 * the same build draws the same pixels. Baselines are Linux renderings, taken by the CI runner:
 * a missing baseline is written to the test output (uploaded with the CI artifacts) for review
 * instead of failing, then committed next to this file.
 */
test.describe('Graph visual regression', { tag: ['@ce'] }, () => {
  test.describe.configure({ mode: 'serial' });
  let fixture: GraphFixture;

  test.beforeAll(async ({ playwright }) => {
    fixture = await withApiRequest(playwright, (request) => createGraphFixture(request, 'visual'));
  });

  test.afterAll(async ({ playwright }) => {
    await withApiRequest(playwright, (request) => deleteGraphFixture(request, fixture));
  });

  const expectGraphScreenshot = async (page: Page, target: Locator, name: string, mask: Locator[] = []) => {
    const info = test.info();
    const options = { animations: 'disabled' as const, mask, maxDiffPixelRatio: 0.01 };
    if (fs.existsSync(info.snapshotPath(name, { kind: 'screenshot' }))) {
      await expect(target).toHaveScreenshot(name, options);
    } else {
      await target.screenshot({ ...options, path: info.outputPath(name) });
      info.annotations.push({ type: 'missing visual baseline', description: name });
    }
    // The documentation shows the same states, taken on the whole page.
    await page.screenshot({ path: info.outputPath(`page-${name}`), animations: 'disabled', mask });
  };

  const arrangeByTier = async (graph: GraphPage, minNodes: number) => {
    await graph.getToolbarButton('Enable the layout by entity tier').click();
    await graph.waitForGraph(minNodes);
  };

  test('knowledge graph laid out by entity tier', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/analyses/reports/${fixture.report.id}/knowledge/graph`);
    await graph.waitForGraph(5);
    await arrangeByTier(graph, 5);
    await expectGraphScreenshot(page, graph.getCanvas(), 'knowledge-graph-tiers.png');
    // The layout is saved per container: switched off so the next test starts from the default.
    await graph.getToolbarButton('Disable the layout by entity tier').click();
  });

  test('focus on a selected entity and its neighbours', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/analyses/reports/${fixture.report.id}/knowledge/graph`);
    await graph.waitForGraph(5);
    await arrangeByTier(graph, 5);
    await graph.clickNode(fixture.malware.id);
    await expect(graph.getSelectionSummary(1)).toBeVisible();
    await page.mouse.move(5, 5);
    await expectGraphScreenshot(page, graph.getCanvas(), 'knowledge-graph-focus.png', [page.locator('.MuiDrawer-paperAnchorRight')]);
    await graph.getToolbarButton('Disable the layout by entity tier').click();
  });

  test('investigation graph in the horizontal tree layout', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/workspaces/investigations/${fixture.investigation.id}`);
    await graph.waitForGraph(3);
    await graph.getToolbarButton('Enable horizontal tree mode').click();
    await graph.waitForGraph(3);
    await expectGraphScreenshot(page, graph.getCanvas(), 'investigation-graph-tree.png');
    await graph.getToolbarButton('Disable horizontal tree mode').click();
  });

  test('correlation graph laid out by entity tier', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/analyses/reports/${fixture.report.id}/knowledge/correlation`);
    await graph.waitForGraph(3);
    await arrangeByTier(graph, 3);
    await expectGraphScreenshot(page, graph.getCanvas(), 'correlation-graph-tiers.png');
    await graph.getToolbarButton('Disable the layout by entity tier').click();
  });
});
