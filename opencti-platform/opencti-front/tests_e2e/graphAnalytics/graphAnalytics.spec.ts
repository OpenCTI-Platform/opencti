import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import GraphAnalyticsPage from '../model/graphAnalytics.pageModel';
import { awaitUntilCondition } from '../utils';
import {
  addAttackPattern,
  addIntrusionSet,
  addRelationship,
  addSector,
  deleteStixCoreObject,
  deleteWorkspace,
  requestGraphRecompute,
  upsertAnalyticsCluster,
} from '../dataForTesting/graphAnalytics.data';

/**
 * Content of the test
 * -------------------
 * Two intrusion sets sharing techniques become similar (Similar tab, side by side comparison)
 * Connect to... finds the path to a sector and starts an investigation with it
 * In the investigation, Find path and Expand by similarity work on the selected nodes
 */
test('Graph analytics: similar entities, paths and investigation tools', { tag: ['@ce', '@graphAnalytics'] }, async ({ page, request }) => {
  test.setTimeout(360000);
  const graphPage = new GraphAnalyticsPage(page);
  const suffix = uuid().slice(0, 8);
  const nameA = `E2E graph analytics set A ${suffix}`;
  const nameB = `E2E graph analytics set B ${suffix}`;
  const techniqueName = `E2E graph analytics technique ${suffix}`;
  const sectorName = `E2E graph analytics sector ${suffix}`;
  const created: string[] = [];
  try {
    const setA = await addIntrusionSet(request, nameA);
    const setB = await addIntrusionSet(request, nameB);
    const technique1 = await addAttackPattern(request, techniqueName, `T9${suffix.slice(0, 3)}`);
    const technique2 = await addAttackPattern(request, `${techniqueName} bis`, `T8${suffix.slice(0, 3)}`);
    const sector = await addSector(request, sectorName);
    created.push(setA, setB, technique1, technique2, sector);
    await addRelationship(request, setA, 'uses', technique1);
    await addRelationship(request, setA, 'uses', technique2);
    await addRelationship(request, setB, 'uses', technique1);
    await addRelationship(request, setB, 'uses', technique2);
    await addRelationship(request, setA, 'targets', sector);

    // region Similar tab, computed in the background by the graph analytics manager
    await requestGraphRecompute(request, [setA, setB]);
    await graphPage.gotoSimilarTab(setA);
    await expect(graphPage.getSimilarTab()).toBeVisible();
    await awaitUntilCondition(async () => {
      await page.reload();
      await graphPage.getSimilarTab().waitFor();
      return graphPage.getSimilarItem(nameB).isVisible();
    }, 10000, 30);
    const similarItem = graphPage.getSimilarItem(nameB);
    await expect(similarItem).toBeVisible();
    // attack patterns are represented with their MITRE identifier
    await expect(similarItem.getByText(`[T9${suffix.slice(0, 3)}] ${techniqueName}`, { exact: true })).toBeVisible();
    await graphPage.getCompareButton().click();
    await expect(graphPage.getCompareColumns()).toHaveCount(2);
    await expect(graphPage.getCompareColumns().nth(0)).toContainText(nameA);
    await expect(graphPage.getCompareColumns().nth(1)).toContainText(nameB);
    await page.keyboard.press('Escape');
    // endregion

    // region Connect to... from the more-actions menu of the second intrusion set
    await page.goto(`/dashboard/threats/intrusion_sets/${setB}`);
    await graphPage.openConnectTo();
    await expect(graphPage.getPathFinder()).toBeVisible();
    await graphPage.getTargetEntityInput().fill(sectorName);
    await page.getByRole('option', { name: sectorName }).click();
    await graphPage.getFindPathsButton().click();
    await expect(graphPage.getPathChains().first()).toBeVisible();
    await expect(graphPage.getPathChains().first()).toContainText(sectorName);
    await expect(graphPage.getPathChains().first()).toContainText(nameA);
    await graphPage.getStartInvestigationButton().click();
    await page.waitForURL(/\/dashboard\/workspaces\/investigations\/.+/);
    // endregion

    // region investigation canvas tools on the selected nodes
    await graphPage.getCanvasSearchInput().fill(`set A ${suffix}`);
    await graphPage.getCanvasSearchInput().press('Enter');
    await expect(graphPage.getExpandBySimilarityToolbarButton()).toBeEnabled();
    await graphPage.getExpandBySimilarityToolbarButton().click();
    await expect(graphPage.getExpandBySimilarityDialog()).toBeVisible();
    await expect(graphPage.getExpandBySimilarityDialog()).toContainText(nameB);
    await page.keyboard.press('Escape');

    await graphPage.getCanvasSearchInput().fill('E2E graph analytics set');
    await graphPage.getCanvasSearchInput().press('Enter');
    await expect(graphPage.getFindPathToolbarButton()).toBeEnabled();
    await graphPage.getFindPathToolbarButton().click();
    await graphPage.getFindPathsButton().click();
    await expect(graphPage.getPathChains().first()).toBeVisible();
    await expect(graphPage.getPathChains().first()).toContainText(`technique ${suffix}`);
    await graphPage.getAddPathsToGraphButton().click();
    await expect(graphPage.getPathFinder()).toBeHidden();
    // endregion
  } finally {
    for (let i = 0; i < created.length; i += 1) {
      await deleteStixCoreObject(request, created[i]);
    }
  }
});

/**
 * Content of the test
 * -------------------
 * A cluster written back by the analytics process is listed and detailed with its members and shared features
 * Create Grouping turns it into a grouping containing the members
 */
test('Graph analytics: clusters list, detail and promotion to a grouping', { tag: ['@ce', '@graphAnalytics'] }, async ({ page, request }) => {
  const graphPage = new GraphAnalyticsPage(page);
  const suffix = uuid().slice(0, 8);
  const nameA = `E2E graph cluster set A ${suffix}`;
  const nameB = `E2E graph cluster set B ${suffix}`;
  const techniqueName = `E2E graph cluster technique ${suffix}`;
  const created: string[] = [];
  try {
    const setA = await addIntrusionSet(request, nameA);
    const setB = await addIntrusionSet(request, nameB);
    const technique = await addAttackPattern(request, techniqueName, `T7${suffix.slice(0, 3)}`);
    created.push(setA, setB, technique);
    // more members than the first page of the promotion preview
    const extraMembers: string[] = [];
    for (let i = 0; i < 5; i += 1) {
      extraMembers.push(await addIntrusionSet(request, `E2E graph cluster set ${i} ${suffix}`));
    }
    created.push(...extraMembers);
    const clusterId = uuid();
    await upsertAnalyticsCluster(request, clusterId, [setA, setB, ...extraMembers], [technique]);

    await graphPage.gotoClusters();
    await expect(graphPage.getClustersPage()).toBeVisible();
    await expect(graphPage.getAnalyticsStatus()).toBeVisible();
    await expect(page.getByTestId('graph-analytics-kpi-clusters')).toBeVisible();
    await expect(page.getByTestId('graph-analytics-kpi-pending')).toBeVisible();

    await graphPage.gotoCluster(clusterId);
    await expect(graphPage.getClusterPage()).toBeVisible();
    await expect(graphPage.getClusterPage().getByText('Techniques (1)')).toBeVisible();
    await expect(graphPage.getClusterMembers().getByText(nameA)).toBeVisible();
    await expect(graphPage.getClusterMembers().getByText(nameB)).toBeVisible();

    const clusterName = (await graphPage.getClusterPage().getByRole('heading', { level: 1 }).textContent()) ?? '';
    // named after what it holds, never after its identifier
    expect(clusterName).toContain('cluster around');
    await graphPage.getCreateGroupingButton().click();
    await expect(page.getByRole('dialog').getByText('Create a grouping of 7 entities')).toBeVisible();
    const preview = page.getByTestId('graph-cluster-promote-preview');
    await expect(preview.getByRole('listitem')).toHaveCount(5);
    await expect(preview.getByText('and 2 more entities')).toBeVisible();
    await page.getByTestId('graph-cluster-promote-preview-more').click();
    await expect(preview.getByRole('listitem')).toHaveCount(7);
    await expect(preview.getByText(nameA)).toBeVisible();
    await expect(page.getByTestId('graph-cluster-promote-preview-more')).toBeHidden();
    await graphPage.getPromoteSubmitButton().click();
    await page.waitForURL(/\/dashboard\/analyses\/groupings\/.+/);
    const groupingId = page.url().split('/groupings/')[1].split('/')[0];
    created.push(groupingId);
    await expect(page.getByText(clusterName).first()).toBeVisible();
  } finally {
    for (let i = 0; i < created.length; i += 1) {
      await deleteStixCoreObject(request, created[i]);
    }
  }
});

/**
 * Content of the test
 * -------------------
 * Create from template > Graph analytics creates a dashboard holding the graph analytics widgets
 */
test('Graph analytics: dashboard template', { tag: ['@ce', '@graphAnalytics'] }, async ({ page, request }) => {
  const graphPage = new GraphAnalyticsPage(page);
  let dashboardId: string | undefined;
  try {
    await graphPage.gotoDashboards();
    await graphPage.getCreateDashboardFromTemplateButton().click();
    await graphPage.getDashboardTemplate('graph-analytics').click();
    await page.waitForURL(/\/dashboard\/workspaces\/dashboards\/[0-9a-f-]{36}/);
    [dashboardId] = page.url().split('/dashboards/')[1].split(/[/?#]/);
    const titles = ['Largest clusters - members over time', 'Similarity of the most connected threats', 'Threat and malware hubs - by degree', 'Infrastructure hubs - by degree', 'Top hubs - by degree'];
    for (let i = 0; i < titles.length; i += 1) {
      await expect(page.getByText(titles[i], { exact: true }).first()).toBeVisible();
    }
  } finally {
    if (dashboardId) await deleteWorkspace(request, dashboardId);
  }
});
