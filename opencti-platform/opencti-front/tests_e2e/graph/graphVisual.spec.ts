import { Locator, Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import GraphPage from '../model/graph.pageModel';
import { createGraphFixture, deleteGraphFixture, GraphFixture, withApiRequest } from '../dataForTesting/graph.data';
import { acquirePlatformThemeLock, getSettings, getThemeIdByName, patchSettings } from '../dataForTesting/settings.data';

/**
 * Visual regression of the graph surfaces, on constant data and deterministic layouts so that
 * the same build draws the same pixels. Baselines are Linux renderings of the CI runner, committed
 * in `graphVisual.spec.ts-snapshots/`: a missing or different baseline fails, and the actual
 * rendering is uploaded with the CI artifacts for review.
 */
// The tests run in order in one worker (no full parallelism). They are not serial: a different rendering of one surface
// fails its test without skipping the others, so one run reports every surface that changed.
test.describe('Graph visual regression', { tag: ['@ce'] }, () => {
  let fixture: GraphFixture;
  let releasePlatformTheme: (() => Promise<void>) | undefined;

  // Run again by the worker that takes over after a failed test
  test.beforeAll(async ({ playwright }) => {
    fixture = await withApiRequest(playwright, (request) => createGraphFixture(request, 'visual'));
  });

  test.afterAll(async ({ playwright }) => {
    if (fixture) await withApiRequest(playwright, (request) => deleteGraphFixture(request, fixture));
  });

  // Every baseline is drawn in a platform theme: no other file may change it while a test draws one. The lock is
  // held per test, so another file never waits for the whole suite within its own test timeout.
  test.beforeEach(async () => {
    releasePlatformTheme = await acquirePlatformThemeLock();
  });

  test.afterEach(async () => {
    await releasePlatformTheme?.();
    releasePlatformTheme = undefined;
  });

  // Soft: a different rendering fails the test once it ends, after it restored the layout it saved on the container
  const expectGraphScreenshot = async (page: Page, target: Locator, name: string, mask: Locator[] = []) => {
    await expect.soft(target).toHaveScreenshot(name, { animations: 'disabled', mask, maxDiffPixelRatio: 0.01 });
    // The toolbar docked under the canvas, neither hovered nor focused: counters, groups, search and More actions.
    await page.mouse.move(5, 5);
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    await expect.soft(new GraphPage(page).getToolbar()).toHaveScreenshot(`toolbar-${name}`, { animations: 'disabled', mask, maxDiffPixelRatio: 0.01 });
    // The documentation shows the same states on the whole page, details panel included.
    await page.screenshot({ path: test.info().outputPath(`page-${name}`), animations: 'disabled' });
  };

  // The documentation shows a list of the toolbar opened as a menu anchored to its tool.
  const captureFilterMenu = async (page: Page, graph: GraphPage, name: string) => {
    if (!(await graph.isInToolbar('Filter by type'))) return;
    await graph.getToolbarButton('Filter by type').click();
    await expect(page.getByRole('menu', { name: 'Filter by type' })).toBeVisible();
    await page.screenshot({ path: test.info().outputPath(name), animations: 'disabled' });
    await page.keyboard.press('Escape');
    await expect(page.getByRole('menu')).toHaveCount(0);
  };

  const arrangeByTier = async (graph: GraphPage, minNodes: number) => {
    await graph.runToolbarAction('Layout by entity tier');
    await graph.waitForGraph(minNodes);
  };

  test('knowledge graph laid out by entity tier', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/analyses/reports/${fixture.report.id}/knowledge/graph`);
    await graph.waitForGraph(5);
    await arrangeByTier(graph, 5);
    await expectGraphScreenshot(page, graph.getCanvas(), 'knowledge-graph-tiers.png');
    await captureFilterMenu(page, graph, 'page-knowledge-graph-filter-menu.png');
    // The layout is saved per container: switched off so the next test starts from the default.
    await graph.runToolbarAction('Layout by entity tier');
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
    await graph.runToolbarAction('Layout by entity tier');
  });

  test('investigation graph in the horizontal tree layout', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/workspaces/investigations/${fixture.investigation.id}`);
    await graph.waitForGraph(3);
    await graph.runToolbarAction('Horizontal tree layout');
    await graph.waitForGraph(3);
    await expectGraphScreenshot(page, graph.getCanvas(), 'investigation-graph-tree.png');
    await graph.runToolbarAction('Horizontal tree layout');
  });

  test('correlation graph laid out by entity tier', async ({ page }) => {
    const graph = new GraphPage(page);
    await page.goto(`/dashboard/analyses/reports/${fixture.report.id}/knowledge/correlation`);
    await graph.waitForGraph(3);
    await arrangeByTier(graph, 3);
    await expectGraphScreenshot(page, graph.getCanvas(), 'correlation-graph-tiers.png');
    await graph.runToolbarAction('Layout by entity tier');
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
      await captureFilterMenu(page, graph, 'page-knowledge-graph-filter-menu-light.png');
      await graph.runToolbarAction('Layout by entity tier');
    } finally {
      await withApiRequest(playwright, (request) => patchSettings(request, settingsId, 'platform_theme', initialThemeId));
    }
  });
});
