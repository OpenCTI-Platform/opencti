import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import CurationPage from '../model/curation.pageModel';
import { addIntrusionSet, deleteDashboard, deleteIntrusionSet, intrusionSetExists, mergeIntrusionSets } from '../dataForTesting/curation.data';

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
test('Unmerge from the Changes tab of the merged entity', { tag: ['@ce'] }, async ({ page, request }) => {
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
    await merges.getByText(targetName).first().click();

    await expect(curationPage.getMergeRecordDetails()).toBeVisible();
    await curationPage.getUnmergeButton().click();
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
test('Create the Knowledge health dashboard from its template', { tag: ['@ce'] }, async ({ page, request }) => {
  await page.goto('/dashboard/workspaces/dashboards');
  await page.getByTestId('CreateDashboardFromTemplate').click();
  await page.getByTestId('dashboard-template-knowledge-health').click();
  await expect(page).toHaveURL(/\/dashboard\/workspaces\/dashboards\/[0-9a-f-]{36}/);
  const dashboardId = page.url().match(/dashboards\/([0-9a-f-]{36})/)?.[1];

  try {
    await expect(page.getByText('Knowledge Health score').first()).toBeVisible();
    await expect(page.getByText('Open curation proposals by kind').first()).toBeVisible();
    await expect(page.getByText('Knowledge Health trend').first()).toBeVisible();
  } finally {
    if (dashboardId) await deleteDashboard(request, dashboardId);
  }
});
