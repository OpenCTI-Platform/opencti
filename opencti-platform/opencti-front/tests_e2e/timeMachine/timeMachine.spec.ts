import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import IntrusionSetPage from '../model/intrusionSet.pageModel';
import IntrusionSetFormPage from '../model/form/intrusionSetForm.pageModel';
import IntrusionSetDetailsPage from '../model/intrusionSetDetails.pageModel';
import TimeMachinePage from '../model/timeMachine.pageModel';
import AutocompleteFieldPageModel from '../model/field/AutocompleteField.pageModel';

const createIntrusionSet = async (page: Page, name: string) => {
  const intrusionSetPage = new IntrusionSetPage(page);
  const intrusionSetForm = new IntrusionSetFormPage(page);
  await page.goto('/dashboard/threats/intrusion_sets');
  await intrusionSetPage.addNewIntrusionSet();
  await intrusionSetForm.fillNameInput(name);
  await intrusionSetPage.getCreateIntrusionSetButton().click();
  await expect(intrusionSetPage.getItemFromList(name)).toBeVisible();
};

test('Time machine: view an entity as of a past date and diff it', { tag: ['@ce'] }, async ({ page }) => {
  const name = `Time machine e2e ${Date.now()}`;
  const intrusionSetPage = new IntrusionSetPage(page);
  const intrusionSetDetailsPage = new IntrusionSetDetailsPage(page);
  const timeMachine = new TimeMachinePage(page);
  await createIntrusionSet(page, name);
  await intrusionSetPage.getItemFromList(name).click();
  await expect(intrusionSetDetailsPage.getIntrusionSetDetailsPage()).toBeVisible();

  // The "View as of" mode opens 30 days back: the entity did not exist yet
  await timeMachine.getAsOfToggle().click();
  await expect(timeMachine.getAsOfOverview()).toBeVisible();
  await expect(timeMachine.getAsOfOverview().getByText('Read-only view of this entity as it was on')).toBeVisible();
  await expect(timeMachine.getSlider()).toBeVisible();
  await expect(timeMachine.getNotExistingMessage()).toBeVisible();
  await timeMachine.backToCurrentKnowledge();
  await expect(timeMachine.getAsOfOverview()).toBeHidden();

  // The Diff tab covers the last 30 days by default: the creation is part of the changes
  await timeMachine.goToDiffTab();
  await expect(page).toHaveURL(/\/diff/);
  await expect(timeMachine.getPeriodSelector()).toBeVisible();
  await expect(timeMachine.getDiff()).toBeVisible();
  await expect(timeMachine.getDiff().getByText('This entity did not exist at the start of the period, its creation is part of the changes.')).toBeVisible();
  await expect(timeMachine.getDiff().getByRole('table', { name: 'Attribute changes' })).toContainText(name);

  // Export of the diff
  const downloadPromise = page.waitForEvent('download');
  await timeMachine.exportDiff('Download as JSON');
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/_diff_\d{4}-\d{2}-\d{2}_\d{4}-\d{2}-\d{2}\.json$/);
});

test('Time machine: compute the landscape changes of intrusion sets and drill down', { tag: ['@ce'] }, async ({ page }) => {
  const timeMachine = new TimeMachinePage(page);
  await createIntrusionSet(page, `Landscape e2e ${Date.now()}`);
  await page.goto('/dashboard/analyses/landscape_changes');
  await expect(timeMachine.getLandscapeChangesPage()).toBeVisible();
  await timeMachine.selectLandscapeEntityType('Intrusion set');
  await timeMachine.computeLandscapeChanges();
  await expect(page).toHaveURL(/[?&]diff=/);
  await expect(timeMachine.getLandscapeChangesResults()).toBeVisible({ timeout: 60000 });
  await expect(timeMachine.getLandscapeEntities()).toBeVisible();

  // Drill down: each changed entity opens its Diff tab on the same period
  await timeMachine.getLandscapeEntities().getByRole('link').first().click();
  await expect(page).toHaveURL(/\/diff\?from=.+&to=.+/);
  await expect(timeMachine.getDiff()).toBeVisible();
});

test('Time machine: create a change digest', { tag: ['@ce'] }, async ({ page }) => {
  const name = `Change digest e2e ${Date.now()}`;
  await page.goto('/dashboard/profile/notifications/triggers');
  await page.getByTestId('change-digest-create').click();
  await expect(page.getByText('Create a change digest')).toBeVisible();
  await page.getByRole('textbox', { name: 'Name' }).fill(name);
  await new AutocompleteFieldPageModel(page, 'Notifiers', true).selectOption('User interface');
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(page.getByText(name)).toBeVisible();
  await expect(page.getByText('Change digest', { exact: true }).first()).toBeVisible();
});

test('Time machine: purge my last visit markers', { tag: ['@ce'] }, async ({ page }) => {
  await page.goto('/dashboard/profile/me');
  await page.getByTestId('purge-last-visits').click();
  await page.getByRole('dialog').getByRole('button', { name: 'Validate' }).click();
  await expect(page.getByText('Your last visit markers have been purged')).toBeVisible();
});
