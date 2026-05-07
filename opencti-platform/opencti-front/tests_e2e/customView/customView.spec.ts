import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import CustomViewsSettingsPage from '../model/customViewsSettings.pageModel';
import CustomViewDetailsPage from '../model/customViewDetails.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import CampaignPage from '../model/campaign.pageModel';
import SettingsCustomizationPage from 'tests_e2e/model/settingsCustomization.pageModel';

/**
 * Content of the test
 * -------------------
 * Golden path for Custom Views feature:
 * 1. Navigate to Settings > Customization > Campaign > Custom Views.
 * 2. Create a new Custom View targeting Campaign entities.
 * 3. Validate form fields (required, min length).
 * 4. Verify the view appears in the list.
 * 5. Add a widget to the view.
 * 6. Enable the view and verify it appears as a tab on a Campaign entity page.
 * 7. Set the view as Default and verify it is the landing tab.
 * 8. Duplicate the view.
 * 9. Export then re-import the view.
 * 10. Delete the view (and its duplicate and the imported view).
 */
test('Custom View CRUD - golden path', { tag: ['@ce'] }, async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);
  const customViewsSettingsPage = new CustomViewsSettingsPage(page);
  const customizationPage = new SettingsCustomizationPage(page);
  const customViewDetailsPage = new CustomViewDetailsPage(page);
  const campaignPage = new CampaignPage(page);

  const viewName = `Custom View - ${uuid()}`;

  // ─── Navigate ────────────────────────────────────────────────────────────────
  await page.goto('/');
  await customViewsSettingsPage.navigateFromMenu(customizationPage, 'Campaign');
  await expect(page.getByRole('heading', { name: 'Campaign' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Custom Views' })).toBeVisible();

  // ─── Open create form ────────────────────────────────────────────────────────
  await customViewsSettingsPage.getAddButton().click();
  await expect(page.getByRole('heading', { name: 'Create custom view' })).toBeVisible();

  // ─── Validate required field ─────────────────────────────────────────────────
  await page.getByRole('button', { name: 'Create' }).click();
  await expect(page.getByText('This field is required')).toBeVisible();

  // ─── Validate min-length ─────────────────────────────────────────────────────
  await page.getByRole('textbox', { name: 'Name' }).fill('a');
  await expect(page.getByText('name must be at least 2 characters')).toBeVisible();

  // ─── Fill form and create ─────────────────────────────────────────────────────
  await page.getByRole('textbox', { name: 'Name' }).fill(viewName);
  await page.getByTestId('text-area').fill('E2E test custom view');
  await page.getByRole('button', { name: 'Create' }).click();

  // ─── Verify we are in view detail / edit mode ────────────────────────────────────────────
  await expect(customViewDetailsPage.getTitle(viewName)).toBeVisible();

  // ─── Add a widget ─────────────────────────────────────────────────────────────
  await customViewDetailsPage.widgets.openWidgetModal();
  await customViewDetailsPage.widgets.selectWidget('List');
  await customViewDetailsPage.widgets.selectPerspective('Entities');
  await expect(page.getByText('In regards of')).toBeVisible();
  await expect(page.getByText('CURRENT ENTITY', { exact: true })).toBeVisible();
  await customViewDetailsPage.widgets.fillLabel('Malwares');
  await customViewDetailsPage.widgets.validateFilters();
  await customViewDetailsPage.widgets.titleField.fill('Related malwares');
  await customViewDetailsPage.widgets.createWidget();
  // Widget should now be visible in the view
  await expect(page.getByText('Related malwares')).toBeVisible();

  // ─── Enable the view ─────────────────────────────────────────────────────────
  await expect(customViewDetailsPage.getViewIsDisabledTag()).toBeVisible();
  await customViewDetailsPage.getEnableToggle().click();
  await expect(customViewDetailsPage.getViewIsEnabledTag()).toBeVisible();

  // ─── Verify view appears in list ─────────────────────────────────────────────
  await page.goto(customViewsSettingsPage.getPageUrl('Campaign'));
  await expect(customViewsSettingsPage.getItemFromList(viewName)).toBeVisible();

  // ─── Verify tab appears on a Campaign entity page ─────────────────────────────
  await leftBarPage.clickOnMenu('Threats', 'Campaigns');
  await campaignPage.getItemFromListWithUrl('menuPass').click();
  // The custom view tab should be visible (single view → uses view name directly)
  await expect(page.getByRole('tab', { name: viewName })).toBeVisible();

  // ─── Set as Default ──────────────────────────────────────────────────────────
  await page.goto(customViewsSettingsPage.getPageUrl('Campaign'));
  await customViewsSettingsPage.getItemFromList(viewName).click();
  await customViewDetailsPage.getEditButton().click();
  await customViewDetailsPage.getDefaultToggle().click();
  await customViewDetailsPage.getCloseButton().click();

  // Verify the default tab is first on a Campaign entity page
  await leftBarPage.clickOnMenu('Threats', 'Campaigns');
  await campaignPage.getItemFromListWithUrl('menuPass').click();
  const tabs = page.getByRole('tab');
  await expect(tabs.first()).toHaveText(viewName);

  // ─── Duplicate ───────────────────────────────────────────────────────────────
  const duplicateName = `${viewName} - copy`;
  await page.goto(customViewsSettingsPage.getPageUrl('Campaign'));
  await customViewsSettingsPage.getItemFromList(viewName).click();
  await customViewDetailsPage.getActionsPopover().click();
  await customViewDetailsPage.getActionButton('Duplicate').click();
  await customViewDetailsPage.getDuplicateButton().click();
  await page.goto(customViewsSettingsPage.getPageUrl('Campaign'));
  await expect(customViewsSettingsPage.getItemFromList(duplicateName)).toBeVisible();

  // ─── Export / Import ─────────────────────────────────────────────────────────
  await customViewsSettingsPage.getItemFromList(viewName).click();
  const downloadPromise = page.waitForEvent('download');
  await customViewDetailsPage.getExportButton().click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBeDefined();
  await download.saveAs(`./test-results/e2e-files/${download.suggestedFilename()}`);

  // Import it back
  await page.goto(customViewsSettingsPage.getPageUrl('Campaign'));
  const fileChooserPromise = page.waitForEvent('filechooser');
  await customViewsSettingsPage.getImportButton().click();
  const fileChooser = await fileChooserPromise;
  await fileChooser.setFiles(`./test-results/e2e-files/${download.suggestedFilename()}`);
  // Imported view should be visible (disabled by default)
  await page.goto(customViewsSettingsPage.getPageUrl('Campaign'));
  const lines = customViewsSettingsPage.getItemFromList(viewName);
  await expect.poll(async () => {
    return await lines.filter({ visible: true }).count();
  }, {
    timeout: 5000,
    intervals: [100, 200, 500],
  }).toBe(2);

  // ─── Cleanup: delete all created views ───────────────────────────────────────
  await page.goto(customViewsSettingsPage.getPageUrl('Campaign'));
  for (const name of [viewName, duplicateName, viewName]) {
    const item = customViewsSettingsPage.getItemFromList(name).nth(0);
    await item.waitFor({ state: 'visible', timeout: 5000 });
    await customViewsSettingsPage.getQuickActionsButton(item).click();
    await customViewsSettingsPage.getDeleteQuickActionButton().click();
    await customViewsSettingsPage.getConfirmButton().click();
  }
  await expect(customViewsSettingsPage.getItemFromList(viewName)).toBeHidden();
});
