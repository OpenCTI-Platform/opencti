import { Locator, Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import GraphPage from '../model/graph.pageModel';
import { createGraphFixture, deleteGraphFixture, GraphFixture, withApiRequest } from '../dataForTesting/graph.data';
import { getSettings, getThemeIdByName, patchSettings } from '../dataForTesting/settings.data';

/**
 * Visual regression of the graph surfaces, on constant data and deterministic layouts so that
 * the same build draws the same pixels. Baselines are Linux renderings of the CI runner, committed
 * in `graphVisual.spec.ts-snapshots/`: a missing or different baseline fails, and the actual
 * rendering is uploaded with the CI artifacts for review.
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
    await expect(target).toHaveScreenshot(name, { animations: 'disabled', mask, maxDiffPixelRatio: 0.01 });
    // The documentation shows the same states on the whole page, details panel included.
    await page.screenshot({ path: test.info().outputPath(`page-${name}`), animations: 'disabled' });
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

  test('knowledge graph in the light theme', async ({ page, playwright }) => {
    // The platform theme is shared by every test: captured first and restored whatever happens.
    const { settingsId, initialThemeId } = await withApiRequest(playwright, async (request) => {
      const settings = await getSettings(request);
      const initial = settings.platform_theme?.id ?? await getThemeIdByName(request, 'Filigran Dark');
      await patchSettings(request, settings.id, 'platform_theme', await getThemeIdByName(request, 'Filigran Light'));
      return { settingsId: settings.id as string, initialThemeId: initial as string };
    });
    try {
      const graph = new GraphPage(page);
      await page.goto(`/dashboard/analyses/reports/${fixture.report.id}/knowledge/graph`);
      await graph.waitForGraph(5);
      await arrangeByTier(graph, 5);
      await expectGraphScreenshot(page, graph.getCanvas(), 'knowledge-graph-tiers-light.png');
      await graph.getToolbarButton('Disable the layout by entity tier').click();
    } finally {
      await withApiRequest(playwright, (request) => patchSettings(request, settingsId, 'platform_theme', initialThemeId));
    }
  });
});
