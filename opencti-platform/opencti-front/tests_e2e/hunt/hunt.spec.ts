import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import HuntsPage from '../model/hunts.pageModel';
import HuntFormPage from '../model/form/huntForm.pageModel';
import HuntDetailsPage from '../model/huntDetails.pageModel';
import { deleteSeededHunt, HUNT_SIGMA_RULE, seedHuntWithCompletedRun } from '../dataForTesting/hunt.data';

const INVALID_SIGMA_RULE = 'title: E2E broken rule\n';

/**
 * Content of the test
 * -------------------
 * Open the hunts list from the menu
 * Create a hunt manually, with the live Sigma validation
 * Navigate through the hunt tabs
 * Validate the Sigma rule from the Logic tab
 * Delete the hunt
 */
test('Hunt manual creation, tabs and Logic validation', { tag: ['@hunt', '@mutation', '@ce'] }, async ({ page }) => {
  const huntsPage = new HuntsPage(page);
  const huntForm = new HuntFormPage(page);
  const huntDetails = new HuntDetailsPage(page);

  // region List
  // -----------
  await huntsPage.goto();
  await expect(huntsPage.getPage()).toBeVisible();
  // endregion

  // region Manual creation
  // ----------------------
  await huntsPage.openCreateForm();
  await expect(huntForm.getCreateTitle()).toBeVisible();
  const huntName = `Hunt - ${uuid()}`;
  await huntForm.getSigmaEditor().fill(INVALID_SIGMA_RULE);
  await expect(huntForm.getSigmaValidation().getByText('Invalid Sigma rule')).toBeVisible();
  await huntForm.getSigmaEditor().fill(HUNT_SIGMA_RULE);
  await expect(huntForm.getSigmaValidation().getByText('Valid Sigma rule')).toBeVisible();
  await huntForm.getNextButton().click();
  await huntForm.nameField.fill(huntName);
  await huntForm.getCreateButton().click();

  await huntsPage.getItemFromList(huntName).click();
  await expect(huntDetails.getTitle(huntName)).toBeVisible();
  await expect(huntDetails.getOverview()).toBeVisible();
  // endregion

  // region Tabs and Logic validation
  // --------------------------------
  await huntDetails.tabs.goToLogicTab();
  await expect(huntDetails.getLogicPage()).toBeVisible();
  await expect(huntDetails.getLogicSigmaValidation().getByText('Valid Sigma rule')).toBeVisible();
  await expect(huntDetails.getLogicSaveButton()).toBeDisabled();
  await huntDetails.getLogicSigmaEditor().fill(INVALID_SIGMA_RULE);
  await expect(huntDetails.getLogicSigmaValidation().getByText('Invalid Sigma rule')).toBeVisible();
  await expect(huntDetails.getLogicSaveButton()).toBeEnabled();
  await huntDetails.getLogicSigmaEditor().fill(HUNT_SIGMA_RULE);
  await expect(huntDetails.getLogicSigmaValidation().getByText('Valid Sigma rule')).toBeVisible();

  await huntDetails.tabs.goToRunsTab();
  await expect(huntDetails.getRunsPage()).toBeVisible();
  await huntDetails.tabs.goToEvidenceTab();
  await expect(huntDetails.getEvidencePage()).toBeVisible();
  await huntDetails.tabs.goToCoverageTab();
  await expect(huntDetails.getCoveragePage()).toBeVisible();
  await huntDetails.tabs.goToHistoryTab();
  await huntDetails.tabs.goToOverviewTab();
  await expect(huntDetails.getOverview()).toBeVisible();
  // endregion

  // region Delete
  // -------------
  await huntDetails.delete();
  await huntsPage.goto();
  await expect(huntsPage.getItemFromList(huntName)).toBeHidden();
  // endregion
});

/**
 * Content of the test
 * -------------------
 * Seed an active hunt with a run a hunt connector reported completed
 * Open the run from the Runs tab of the hunt and read its page
 * Save an analyst verdict, then go back to the hunt
 */
test('Hunt run page verdict', { tag: ['@hunt', '@mutation', '@ce'] }, async ({ page, request }) => {
  const huntDetails = new HuntDetailsPage(page);
  const huntName = `Hunt with a run - ${uuid()}`;
  const seeded = await seedHuntWithCompletedRun(request, huntName);
  try {
    await huntDetails.gotoRuns(seeded.huntId);
    await huntDetails.getRunRow(seeded.huntId, seeded.runId).click();
    await expect(page).toHaveURL(new RegExp(`/dashboard/defense/hunts/${seeded.huntId}/runs/${seeded.runId}$`));
    await expect(huntDetails.getRunPage()).toBeVisible();
    await expect(huntDetails.getRunsPage()).toBeHidden();
    const header = huntDetails.getRunHeader();
    await expect(header.getByRole('heading', { name: /^Run of / })).toBeVisible();
    await expect(header.getByTestId('hunt-run-hunt-name')).toHaveText(huntName);
    await expect(page.getByTestId('navigation').getByRole('link', { name: huntName })).toBeVisible();
    await expect(page.getByTestId('hunt-run-status-sentence')).toContainText('3 hits');
    await expect(page.getByTestId('hunt-run-evidence')).toContainText('WS-E2E-01');
    await expect(huntDetails.getRunVerdictForm()).toBeVisible();
    // The pending run proposes a true positive, which offers the incident; another verdict does not
    const incidentChoice = huntDetails.getRunVerdictIncidentChoice();
    await expect(incidentChoice).toBeVisible();
    await expect(incidentChoice.getByText('The hits go to the open incident of this hunt, or to a new incident draft')).toBeVisible();
    // Without escalation, the helper says what is recorded
    await incidentChoice.getByText('Escalate to an incident', { exact: true }).click();
    await expect(incidentChoice.getByText('Only the verdict is recorded')).toBeVisible();
    await huntDetails.verdictField.selectOption('Benign');
    await expect(huntDetails.getRunVerdictIncidentChoice()).toBeHidden();
    await huntDetails.saveRunVerdict();
    await expect(page.getByText('The verdict has been saved')).toBeVisible();
    await expect(huntDetails.getVerdictChip('Benign')).toBeVisible();
    await huntDetails.getRunBackButton().click();
    await expect(huntDetails.getRunsPage()).toBeVisible();
    await expect(huntDetails.getRunPage()).toBeHidden();
  } finally {
    await deleteSeededHunt(request, seeded);
  }
});
