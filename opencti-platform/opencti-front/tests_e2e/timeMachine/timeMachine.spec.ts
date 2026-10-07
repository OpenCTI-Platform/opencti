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

  // "View as of" from the more actions menu opens the Changes tab 30 days back: the entity did not exist yet
  await timeMachine.openViewAsOfFromMenu();
  await expect(page).toHaveURL(/\/changes\?section=as-of/);
  await expect(timeMachine.getAsOfSection()).toBeVisible();
  await expect(timeMachine.getAsOfSection().getByText('Read-only view of this entity as it was on')).toBeVisible();
  await expect(timeMachine.getSlider()).toBeVisible();
  await expect(timeMachine.getNotExistingMessage()).toBeVisible();
  // The empty view offers its next action: the first recorded change, the creation of the entity
  await timeMachine.getNotExistingMessage().getByRole('button', { name: 'Go to the first recorded change' }).click();
  await expect(timeMachine.getAsOfView()).toBeVisible();
  await expect(timeMachine.getNotExistingMessage()).toBeHidden();
  await timeMachine.backToCurrentKnowledge();
  await expect(page).toHaveURL(/\/overview/);
  await expect(timeMachine.getAsOfSection()).toBeHidden();

  // The Changes tab compares the last 30 days by default: the creation is part of the changes
  await timeMachine.goToChangesTab();
  await expect(page).toHaveURL(/\/changes/);
  await expect(timeMachine.getPeriodSelector()).toBeVisible();
  await expect(timeMachine.getDiff()).toBeVisible();
  await expect(timeMachine.getDiff().getByText('This entity did not exist at the start of the period, its creation is part of the changes.')).toBeVisible();
  await expect(timeMachine.getDiff().getByRole('table', { name: 'Attribute changes' })).toContainText(name);
  // Each row names its operation: the attributes set at the creation are added
  await expect(timeMachine.getDiff().getByRole('table', { name: 'Attribute changes' }).getByText('Added').first()).toBeVisible();

  // Both sections of the Changes tab are one click away from each other
  await timeMachine.goToChangesSection('View as of');
  await expect(timeMachine.getAsOfSection()).toBeVisible();
  await expect(timeMachine.getDiff()).toBeHidden();
  await timeMachine.goToChangesSection('Compare dates');
  await expect(timeMachine.getDiff()).toBeVisible();

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
  await timeMachine.selectLandscapeEntityType('Intrusion Set');
  await timeMachine.computeLandscapeChanges();
  await expect(page).toHaveURL(/[?&]diff=/);
  await expect(timeMachine.getLandscapeChangesResults()).toBeVisible({ timeout: 60000 });
  await expect(timeMachine.getLandscapeEntities()).toBeVisible();

  // Drill down: each changed entity opens its Changes tab on the same period
  await timeMachine.getLandscapeEntities().getByRole('link').first().click();
  await expect(page).toHaveURL(/\/changes\?section=compare&from=.+&to=.+/);
  await expect(timeMachine.getDiff()).toBeVisible();
});

test('Time machine: create the threat landscape changes dashboard from its template', { tag: ['@ce'] }, async ({ page }) => {
  await page.goto('/dashboard/workspaces/dashboards');
  await page.getByTestId('CreateDashboardFromTemplate').click();
  await page.getByTestId('dashboard-template-landscape-changes').click();
  await expect(page).toHaveURL(/\/dashboard\/workspaces\/dashboards\/[0-9a-f-]{36}/);
  await expect(page.getByText('Top changed threats')).toBeVisible();
  await expect(page.getByText('New techniques of the threats by tactic')).toBeVisible();
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
