import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import DashboardPage from '../model/dashboard.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import DashboardFormPage from '../model/form/dashboardForm.pageModel';
import DashboardWidgetsPageModel from '../model/DashboardWidgets.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import MalwareDetailsPage from '../model/malwareDetails.pageModel';

// Because of login/logout stuff in access restriction test below, running
// both in parallel make conflicts.
// Need to be resolved in an other way but for now we do it like this.
test.describe.configure({ mode: 'serial' });

/**
 * Content of the test
 * -------------------
 * Check open/close form.
 * Check fields validation in the form.
 * Create a new dashboard.
 * Check data of listed dashboards.
 * Check details of a dashboard.
 * Update dashboard name.
 * Delete a dashboard.
 * Export/Import a dashboard.
 * Create Widget - see values - Delete Widget
 */
test('Dashboard CRUD', async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);
  const dashboardPage = new DashboardPage(page);
  const dashboardForm = new DashboardFormPage(page, 'Create dashboard');
  const dashboardUpdateForm = new DashboardFormPage(page, 'Update dashboard');
  const widgetsPage = new DashboardWidgetsPageModel(page);
  const malwareDetailsPage = new MalwareDetailsPage(page);
  const dashboardDetailsPage = new DashboardDetailsPage(page);

  await page.goto('/dashboard/workspaces/dashboards');
  await leftBarPage.open();

  const dashboardName = `Dashboard - ${uuid()}`;
  const updateDashboardName = `Updated - ${uuid()}`;

  // region Check open/close form.
  // -----------------------------

  await dashboardPage.getAddNewDashboardButton().click();
  await expect(dashboardForm.getCreateTitle()).toBeVisible();
  await dashboardForm.getCancelButton().click();
  await expect(dashboardForm.getCreateTitle()).toBeHidden();
  await dashboardPage.getAddNewDashboardButton().click();
  await expect(dashboardForm.getCreateTitle()).toBeVisible();

  // ---------
  // endregion

  // region Fields validation in the form and create.
  // ------------------------------------------------

  await dashboardForm.nameField.fill('');
  await dashboardForm.getCreateButton().click();
  await expect(page.getByText('This field is required')).toBeVisible();
  await dashboardForm.nameField.fill('a');
  await expect(page.getByText('Name must be at least 2 characters')).toBeVisible();
  await dashboardForm.nameField.fill(dashboardName);
  await expect(page.getByText('Name must be at least 2 characters')).toBeHidden();

  await dashboardForm.descriptionField.fill('Test e2e Description');
  await expect(dashboardForm.descriptionField.get()).toHaveValue('Test e2e Description');
  await dashboardForm.getCreateButton().click();

  // ---------
  // endregion

  // region Check data of listed dashboards.
  // ---------------------------------------

  await expect(dashboardPage.getItemFromList(dashboardName)).toBeVisible();

  // ---------
  // endregion

  // region Check details of a dashboard.
  // ------------------------------------

  await dashboardPage.getItemFromList(dashboardName).click();
  await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();
  await expect(dashboardDetailsPage.getTitle(dashboardName)).toBeVisible();
  await dashboardDetailsPage.getEditButton().click();
  expect(await dashboardUpdateForm.descriptionField.value()).toEqual('Test e2e Description');
  await dashboardUpdateForm.getCloseButton().click();

  // ---------
  // endregion

  // region Update dashboard properties
  // ----------------------------------

  await dashboardDetailsPage.getEditButton().click();
  await expect(dashboardUpdateForm.getUpdateTitle()).toBeVisible();
  await dashboardUpdateForm.nameField.fill(updateDashboardName);
  await dashboardUpdateForm.getUpdateTitle().click();
  await dashboardUpdateForm.getCloseButton().click();
  await expect(dashboardDetailsPage.getTitle(updateDashboardName)).toBeVisible();

  // ---------
  // endregion

  // region Check that dashboard have correct data
  // ---------------------------------------------

  await leftBarPage.clickOnMenu('Dashboards', 'Custom dashboards');
  await dashboardPage.getItemFromList(updateDashboardName).click();
  await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();

  await expect(dashboardDetailsPage.startDateField.getInput()).toBeEnabled();
  await dashboardDetailsPage.accessSelect.selectOption('Last year');
  await expect(dashboardDetailsPage.startDateField.getInput()).toBeDisabled();

  // ---------
  // endregion

  // region Duplicate a dashboard
  // ----------------------------

  const duplicateDashboardName = `${updateDashboardName} - copy`;
  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Duplicate').click();
  await dashboardDetailsPage.getDuplicateButton().click();

  await leftBarPage.clickOnMenu('Dashboards', 'Custom dashboards');
  await expect(dashboardPage.getItemFromList(duplicateDashboardName)).toBeVisible();
  await dashboardPage.getItemFromList(duplicateDashboardName).click();
  await expect(dashboardDetailsPage.getTitle(duplicateDashboardName)).toBeVisible();

  // ---------
  // endregion

  // region Delete a dashboard
  // -------------------------

  await dashboardDetailsPage.delete();
  await page.waitForTimeout(1000); // After delete need to wait a bit
  await leftBarPage.clickOnMenu('Dashboards', 'Custom dashboards');
  await expect(dashboardPage.getPageTitle()).toBeVisible();
  await expect(dashboardPage.getItemFromList(duplicateDashboardName)).toBeHidden();

  // ---------
  // endregion

  // region Export/Import dashboard
  // ------------------------------

  // From dashboard overview - export
  await leftBarPage.clickOnMenu('Dashboards', 'Custom dashboards');
  await dashboardPage.getItemFromList(updateDashboardName).click();
  const downloadPromise = page.waitForEvent('download');
  await dashboardDetailsPage.getExportButton().click();
  await page.mouse.click(10, 10); // To close action menu
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBeDefined();
  await download.saveAs(`./test-results/e2e-files/${download.suggestedFilename()}`);

  // From list page - import
  await leftBarPage.clickOnMenu('Dashboards', 'Custom dashboards');
  let fileChooserPromise = page.waitForEvent('filechooser');
  await dashboardPage.getImportDashboardButton().click();
  let fileChooser = await fileChooserPromise;
  await fileChooser.setFiles(`./test-results/e2e-files/${download.suggestedFilename()}`);
  await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();
  await expect(dashboardDetailsPage.getTitle(updateDashboardName)).toBeVisible();
  await dashboardDetailsPage.delete();
  await page.waitForTimeout(1000);// After delete need to wait a bit

  // Import dashboard with exhaustive list of widgets
  await leftBarPage.clickOnMenu('Dashboards', 'Custom dashboards');
  fileChooserPromise = page.waitForEvent('filechooser');
  await dashboardPage.getImportDashboardButton().click();
  fileChooser = await fileChooserPromise;
  await fileChooser.setFiles('./tests_e2e/dashboard/dashboard_e2e.json');
  await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();
  await expect(dashboardDetailsPage.getTitle('Full Dashboard')).toBeVisible();
  const errors = page.getByText('An unknown error occurred.');
  await expect(errors).toHaveCount(0);

  await expect(dashboardDetailsPage.getExportPDFButton()).toBeVisible();

  // Export dashboard as PDF, should succeed to get a file.
  // Dark mode
  const downloadPDFPromiseDark = page.waitForEvent('download');
  await dashboardDetailsPage.getExportPDFButton().click();
  await dashboardDetailsPage.getExportPDFButtonThemeMenu('Dark').click();

  const downloadPdfDark = await downloadPDFPromiseDark;
  expect(downloadPdfDark.suggestedFilename()).toBeDefined();
  await downloadPdfDark.saveAs(`./test-results/e2e-files/${downloadPdfDark.suggestedFilename()}`);
  // Light mode
  const downloadPDFPromiseLight = page.waitForEvent('download');
  await dashboardDetailsPage.getExportPDFButton().click();
  await dashboardDetailsPage.getExportPDFButtonThemeMenu('Light').click();

  const downloadPdfLight = await downloadPDFPromiseLight;
  expect(downloadPdfLight.suggestedFilename()).toBeDefined();
  await downloadPdfLight.saveAs(`./test-results/e2e-files/${downloadPdfLight.suggestedFilename()}`);
  // End Export dashboard as PDF

  // Delete imported dashboard
  await dashboardDetailsPage.delete();
  await page.waitForTimeout(1000); // After delete need to wait a bit
  // ---------
  // endregion

  // region Create Widget - see values - Delete Widget
  // -------------------------

  const malwareName = 'E2E dashboard - Malware - 6 months ago';
  await dashboardPage.getItemFromList(updateDashboardName).click();
  await widgetsPage.createListOfMalwaresWidget();
  await widgetsPage.getItemFromWidgetList(malwareName).click();
  await expect(malwareDetailsPage.getTitle(malwareName)).toBeVisible();

  await leftBarPage.clickOnMenu('Dashboards', 'Custom dashboards');
  await dashboardPage.getItemFromList(updateDashboardName).click();
  await widgetsPage.getActionsWidgetsPopover().click();
  await widgetsPage.getActionButton('Delete').click();
  await widgetsPage.getConfirmButton().click();
  await page.waitForTimeout(1000);// After delete need to wait a bit

  await widgetsPage.createTimelineOfMalwaresWidget();
  await widgetsPage.getItemFromWidgetTimeline(malwareName).click();
  await expect(malwareDetailsPage.getTitle(malwareName)).toBeVisible();

  await widgetsPage.getIconFromWidgetTimeline().click();
  await expect(malwareDetailsPage.getTitle(malwareName)).toBeVisible();

  // ---------
  // endregion

  // region Interact with start and end date CTA - change value in widgets
  // -------------------------

  await leftBarPage.clickOnMenu('Dashboards', 'Custom dashboards');
  await dashboardPage.getItemFromList(updateDashboardName).click();
  await dashboardDetailsPage.accessSelect.selectOption('None');

  await widgetsPage.createNumberOfEntities();
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '46')).toBeVisible();

  // Manipulating field "Start date"
  await dashboardDetailsPage.startDateField.fill('05/19/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '22')).toBeVisible();
  await dashboardDetailsPage.startDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.startDateField.fill('05/12/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '29')).toBeVisible();
  await dashboardDetailsPage.startDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.startDateField.fill('04/17/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '36')).toBeVisible();
  await dashboardDetailsPage.startDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.startDateField.fill('12/17/2023');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '43')).toBeVisible();
  await dashboardDetailsPage.startDateField.clear();

  // Manipulating field "End date"
  await dashboardDetailsPage.endDateField.fill('12/20/2023');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '10')).toBeVisible();
  await dashboardDetailsPage.endDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.endDateField.fill('04/19/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '17')).toBeVisible();
  await dashboardDetailsPage.endDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  // ----> Comment this part for now as the number "24" is making a conflict with 24 hours
  // await dashboardDetailsPage.endDateField.fill('05/20/2024');
  // await expect(widgetsPage.getWidgetNumberValue('Number of entities', '24')).toBeVisible();
  // await dashboardDetailsPage.endDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.endDateField.fill('05/21/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '31')).toBeVisible();
  await dashboardDetailsPage.endDateField.clear();

  // ---------
  // endregion

  await leftBarPage.clickOnMenu('Dashboards', 'Custom dashboards');
  await dashboardPage.getItemFromList(updateDashboardName).click();
  await dashboardDetailsPage.delete();
  await page.waitForTimeout(1000);// After delete need to wait a bit
});
