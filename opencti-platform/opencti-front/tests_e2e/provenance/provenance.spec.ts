import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import IntrusionSetPage from '../model/intrusionSet.pageModel';
import IntrusionSetFormPage from '../model/form/intrusionSetForm.pageModel';
import IntrusionSetDetailsPage from '../model/intrusionSetDetails.pageModel';

test('Navigate the provenance tabs of the curation hub', { tag: ['@ce'] }, async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);

  await page.goto('/dashboard/data/curation/conflicts');
  await leftBarPage.expectBreadcrumb('Data', 'Curation', 'Conflicts');
  await expect(page.getByTestId('provenance-conflicts-page')).toBeVisible();
  await page.getByRole('tab', { name: 'Relationships' }).click();
  await expect(page.getByRole('tab', { name: 'Relationships' })).toHaveAttribute('aria-selected', 'true');

  await page.getByTestId('curation-tab-stale-knowledge').click();
  await leftBarPage.expectBreadcrumb('Data', 'Curation', 'Stale knowledge');
  await expect(page.getByTestId('provenance-stale-page')).toBeVisible();
});

test('Follow the provenance backfill and the procedures parameters', { tag: ['@ce'] }, async ({ page }) => {
  await page.goto('/dashboard/data/processing/tasks');
  await expect(page.getByTestId('provenance-backfill')).toBeVisible();
  await expect(page.getByTestId('provenance-backfill-status')).toBeVisible();

  await page.goto('/dashboard/settings');
  await expect(page.getByTestId('settings-procedures')).toBeVisible();
});

test('Display the sources of a created entity and confirm it', { tag: ['@ce'] }, async ({ page }) => {
  const intrusionSetPage = new IntrusionSetPage(page);
  const intrusionSetForm = new IntrusionSetFormPage(page);
  const intrusionSetDetailsPage = new IntrusionSetDetailsPage(page);
  const intrusionSetName = `Provenance e2e ${uuid()}`;

  await page.goto('/dashboard/threats/intrusion_sets');
  await intrusionSetPage.addNewIntrusionSet();
  await intrusionSetForm.fillNameInput(intrusionSetName);
  await intrusionSetPage.getCreateIntrusionSetButton().click();
  await intrusionSetPage.getItemFromList(intrusionSetName).click();
  await expect(intrusionSetDetailsPage.getIntrusionSetDetailsPage()).toBeVisible();

  // The creating user is the first source of the entity, listed by the Sources card of the overview
  const sourcesCard = page.getByTestId('provenance-sources-card');
  await expect(sourcesCard).toBeVisible();
  await expect(sourcesCard.getByTestId('provenance-source-item')).toHaveCount(1);
  await page.getByTestId('provenance-open-sources').click();
  const panel = page.getByTestId('provenance-sources-panel');
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId('provenance-source-row')).toHaveCount(1);

  // Confirming re-asserts the entity in the name of the current user
  await panel.getByTestId('provenance-assert').click();
  await expect(page.getByText('You confirmed this knowledge')).toBeVisible();
  await expect(panel.getByTestId('provenance-source-row')).toHaveCount(1);
});

test('Create a knowledge decay rule', { tag: ['@ce'] }, async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);
  const ruleName = `Knowledge decay e2e ${uuid()}`;

  await page.goto('/dashboard/settings/customization/decay');
  await leftBarPage.expectBreadcrumb('Settings', 'Customization', 'Decay rules');
  await page.getByRole('tab', { name: 'Knowledge decay rules' }).click();
  await expect(page.getByTestId('knowledge-decay-rules-page')).toBeVisible();

  // Built-in knowledge decay rules are shipped disabled
  await expect(page.getByText('Built-in communicates-with freshness')).toBeVisible();

  await page.getByTestId('create-decayrule-button').click();
  const form = page.getByTestId('knowledge-decay-rule-form');
  await expect(form).toBeVisible();
  await form.getByLabel('Name', { exact: true }).fill(ruleName);
  await page.getByTestId('knowledge-decay-rule-submit').click();
  await expect(form).toBeHidden();
  await expect(page.getByText(ruleName)).toBeVisible();

  await page.getByText(ruleName).click();
  await expect(page.getByTestId('knowledge-decay-rule-view')).toBeVisible();
  await expect(page.getByTestId('knowledge-decay-rule-stale-count')).toBeVisible();
});
