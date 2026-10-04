import { v4 as uuid } from 'uuid';
import type { Page, TestInfo } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import CurationPage from '../model/curation.pageModel';
import SearchPageModel from '../model/search.pageModel';
import { addIntrusionSet, deleteDashboard, deleteIntrusionSet, intrusionSetExists, mergeIntrusionSets, openProposalIds } from '../dataForTesting/curation.data';

// The screenshots of the user documentation (docs/docs/usage/assets/curation-<surface>-<state>.png) are the captures
// of these tests, taken at the documented size and kept with the test results.
test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

const capture = async (page: Page, testInfo: TestInfo, name: string) => {
  await page.screenshot({ path: testInfo.outputPath(`curation-${name}.png`) });
};

/** Answers the curation statistics as on a platform where no proposal was ever raised. */
const withoutAnyProposal = async (page: Page) => {
  await page.route('**/graphql', async (route) => {
    if (!(route.request().postData() ?? '').includes('query CurationStatisticsBarQuery')) {
      await route.fallback();
      return;
    }
    const response = await route.fetch();
    const body = await response.json();
    const statistics = body?.data?.curationStatistics;
    if (statistics) {
      statistics.open_count = 0;
      statistics.ambiguous_count = 0;
      statistics.decided_by_status = [];
    }
    await route.fulfill({ response, json: body });
  });
};

/**
 * Content of the test
 * -------------------
 * Inbox on first use: with no proposal ever raised, the Inbox explains what fills it and when the next scan runs.
 */
test('Curation inbox on first use', { tag: ['@ce'] }, async ({ page }, testInfo) => {
  const curationPage = new CurationPage(page);
  await withoutAnyProposal(page);
  await curationPage.gotoHub();
  const firstUse = page.getByTestId('curation-inbox-first-use');
  await expect(firstUse).toBeVisible();
  await expect(page.getByTestId('curation-inbox-first-use-schedule')).toBeVisible();
  await capture(page, testInfo, 'inbox-first-use');
});

/**
 * Content of the test
 * -------------------
 * Placement of autonomous curation (information architecture directive):
 * 1. Data > Curation opens the Inbox tab, and the Merges and Knowledge health tabs open from the hub tabs.
 * 2. Settings > Customization > Curation holds the curation settings and the curation policies.
 */
test('Curation hub and customization page', { tag: ['@ce'] }, async ({ page }) => {
  const curationPage = new CurationPage(page);

  await curationPage.gotoHub();
  await expect(page).toHaveURL(/\/dashboard\/data\/curation\/inbox(\?.*)?$/);
  await expect(curationPage.getInbox()).toBeVisible();

  await curationPage.getHubTab('merges').click();
  await expect(curationPage.getMerges()).toBeVisible();

  await curationPage.getHubTab('health').click();
  await expect(curationPage.getKnowledgeHealth()).toBeVisible();

  await curationPage.gotoCustomization();
  await expect(page).toHaveURL(/\/dashboard\/settings\/customization\/curation\/settings(\?.*)?$/);
  await expect(curationPage.getCustomization()).toBeVisible();
  await expect(curationPage.getSettings()).toBeVisible();
  await curationPage.getCustomizationTab('policies').click();
  await expect(curationPage.getPolicies()).toBeVisible();
  await expect(page).toHaveURL(/\/dashboard\/settings\/customization\/curation\/policies(\?.*)?$/);
});

/**
 * Content of the test
 * -------------------
 * Reversible merge, from the entity:
 * 1. Two intrusion sets are created and merged through the API.
 * 2. The Merges view of the surviving entity's Changes tab lists the merge.
 * 3. The merge record drawer reverts it (Unmerge), and the merged entity exists again.
 */
test('Unmerge from the Changes tab of the merged entity', { tag: ['@ce'] }, async ({ page, request }, testInfo) => {
  const curationPage = new CurationPage(page);
  const suffix = uuid().slice(0, 8);
  const targetName = `Curation e2e target ${suffix}`;
  const sourceName = `Curation e2e source ${suffix}`;
  const targetId = await addIntrusionSet(request, targetName);
  const sourceId = await addIntrusionSet(request, sourceName);

  try {
    await mergeIntrusionSets(request, targetId, sourceId);
    expect(await intrusionSetExists(request, sourceId)).toBe(false);

    await curationPage.gotoEntityMerges(`/dashboard/threats/intrusion_sets/${targetId}`);
    await expect(curationPage.getChangesTab()).toBeVisible();
    const merges = curationPage.getEntityMerges();
    await expect(merges).toBeVisible();
    await expect(merges.getByText(targetName).first()).toBeVisible();
    await capture(page, testInfo, 'entity-merges');
    await merges.getByText(targetName).first().click();

    await expect(curationPage.getMergeRecordDetails()).toBeVisible();
    await expect(curationPage.getUnmergeButton()).toBeVisible();
    await capture(page, testInfo, 'merge-record-undo');
    await curationPage.getUnmergeButton().click();
    await expect(page.getByTestId('merge-record-unmerge-preview')).toContainText(sourceName);
    await curationPage.getUnmergeConfirmButton().click();
    await expect(curationPage.getUnmergeButton()).toBeHidden({ timeout: 30000 });
    await expect.poll(() => intrusionSetExists(request, sourceId), { timeout: 30000 }).toBe(true);
  } finally {
    await deleteIntrusionSet(request, sourceId);
    await deleteIntrusionSet(request, targetId);
  }
});

/**
 * Content of the test
 * -------------------
 * Knowledge health dashboard template:
 * 1. "Create from template" > "Knowledge health" creates a dashboard and opens it.
 * 2. The dashboard shows the three Knowledge Health widgets of the catalog.
 */
test('Create the Knowledge health dashboard from its template', { tag: ['@ce'] }, async ({ page, request }, testInfo) => {
  await page.goto('/dashboard/workspaces/dashboards');
  await page.getByTestId('CreateDashboardFromTemplate').click();
  await page.getByTestId('dashboard-template-knowledge-health').click();
  await expect(page).toHaveURL(/\/dashboard\/workspaces\/dashboards\/[0-9a-f-]{36}/);
  const dashboardId = page.url().match(/dashboards\/([0-9a-f-]{36})/)?.[1];

  try {
    await expect(page.getByText('Knowledge health score').first()).toBeVisible();
    await expect(page.getByText('Open curation proposals by kind').first()).toBeVisible();
    await expect(page.getByText('Knowledge health trend').first()).toBeVisible();
    await capture(page, testInfo, 'dashboard-template');
  } finally {
    if (dashboardId) await deleteDashboard(request, dashboardId);
  }
});

/**
 * Content of the test
 * -------------------
 * From detection to decision, on the running platform:
 * 1. Two intrusion sets whose names differ only by case and punctuation are created; the curation manager raises a
 *    merge proposal from the stream.
 * 2. The Inbox lists it, and its page compares the subjects and explains the evidence.
 * 3. The surviving entity shows the Possible duplicate chip.
 * 4. Knowledge health is refreshed and shows a snapshot; Settings > Customization > Curation shows the settings and
 *    the policies.
 */
test('Curation proposal from detection to decision', { tag: ['@ce'] }, async ({ page, request }, testInfo) => {
  test.setTimeout(400000);
  const curationPage = new CurationPage(page);
  const suffix = `${Math.floor(1000 + Math.random() * 9000)}`;
  const firstName = `Velvet Lynx ${suffix}`;
  const secondName = `velvet-lynx ${suffix}`;
  const firstId = await addIntrusionSet(request, firstName);
  const secondId = await addIntrusionSet(request, secondName);

  try {
    await expect.poll(async () => (await openProposalIds(request, firstId)).length, { timeout: 240000, intervals: [5000] }).toBeGreaterThan(0);
    const [proposalId] = await openProposalIds(request, firstId);

    await curationPage.gotoHub();
    await expect(curationPage.getInbox()).toBeVisible();
    await expect(page.getByTestId('curation-statistics')).toBeVisible();
    await capture(page, testInfo, 'inbox-kpis');
    // The counters of the strip filter the table below.
    await page.getByTestId('curation-stat-needs-decision').click();
    await expect(page.getByTestId('curation-stat-needs-decision')).toHaveAttribute('data-active', 'true');
    await page.getByTestId('curation-stat-open').click();
    await expect(page.getByTestId('curation-stat-open')).toHaveAttribute('data-active', 'true');
    await new SearchPageModel(page).addSearch(suffix);
    await expect(curationPage.getInbox().getByText(firstName).first()).toBeVisible();
    await capture(page, testInfo, 'inbox-search');

    await page.goto(`/dashboard/data/curation/inbox/${proposalId}`);
    await expect(page.getByTestId('curation-proposal-page')).toBeVisible();
    await expect(page.getByTestId('curation-proposal-summary')).toBeVisible();
    await expect(page.getByTestId('curation-compare-table')).toBeVisible();
    await capture(page, testInfo, 'proposal-compare');
    await page.getByTestId('curation-evidence-table').scrollIntoViewIfNeeded();
    await expect(page.getByTestId('curation-evidence-share').first()).toBeVisible();
    await capture(page, testInfo, 'proposal-evidence');
    await page.getByTestId('curation-proposal-review').click();
    await expect(page.getByTestId('curation-accept-preview')).toBeVisible();
    await capture(page, testInfo, 'proposal-accept-dialog');
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByTestId('curation-accept-preview')).toBeHidden();

    await page.goto(`/dashboard/threats/intrusion_sets/${firstId}`);
    await expect(page.getByTestId('curation-possible-duplicate')).toBeVisible();
    await capture(page, testInfo, 'possible-duplicate-chip');

    await curationPage.gotoHub();
    await curationPage.getHubTab('merges').click();
    await expect(curationPage.getMerges()).toBeVisible();
    await capture(page, testInfo, 'merges-list');

    await curationPage.getHubTab('health').click();
    await expect(curationPage.getKnowledgeHealth()).toBeVisible();
    const healthStatus = page.getByTestId('knowledge-health-status');
    const statusBeforeRefresh = (await healthStatus.textContent()) ?? '';
    await page.getByTestId('knowledge-health-refresh').click();
    await expect(page.getByText('The Knowledge health snapshot has been refreshed')).toBeVisible({ timeout: 120000 });
    await expect(healthStatus).not.toHaveText(statusBeforeRefresh, { timeout: 60000 });
    await expect(page.getByTestId('knowledge-health-score')).toBeVisible();
    await capture(page, testInfo, 'knowledge-health');

    await curationPage.gotoCustomization();
    await expect(curationPage.getSettings()).toBeVisible();
    await capture(page, testInfo, 'settings');
    await curationPage.getCustomizationTab('policies').click();
    await expect(curationPage.getPolicies()).toBeVisible();
    await capture(page, testInfo, 'policies');
  } finally {
    await deleteIntrusionSet(request, secondId);
    await deleteIntrusionSet(request, firstId);
  }
});
