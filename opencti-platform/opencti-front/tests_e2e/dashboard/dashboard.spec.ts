import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import DashboardPage from '../model/dashboard.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import DashboardFormPage from '../model/form/dashboardForm.pageModel';
import DashboardWidgetsPageModel from '../model/DashboardWidgets.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import MalwareDetailsPage from '../model/malwareDetails.pageModel';

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
 */
test('Dashboard CRUD', async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);
  const dashboardPage = new DashboardPage(page);
  const dashboardForm = new DashboardFormPage(page);
  const widgetsPage = new DashboardWidgetsPageModel(page);
  const malwareDetailsPage = new MalwareDetailsPage(page);
  const dashboardDetailsPage = new DashboardDetailsPage(page);

  await page.goto('/dashboard/workspaces/dashboards');
  await leftBarPage.open();

  const dashboardsMenu = 'Dashboards';
  const dashboardName = `Dashboard - ${uuid()}`;
  const updateDashboardName = `UpdateDashboard - ${uuid()}`;

  // region Check open/close form.
  // -----------------------------

  await dashboardPage.getCreateMenuButton().hover();
  await expect(dashboardPage.getAddNewButton()).toBeVisible();
  await expect(dashboardPage.getImportButton()).toBeVisible();
  await dashboardPage.getAddNewButton().click();
  await expect(dashboardForm.getCreateTitle()).toBeVisible();
  await dashboardForm.getCancelButton().click();
  await expect(dashboardForm.getCreateTitle()).toBeHidden();
  await dashboardPage.getCreateMenuButton().hover();
  await dashboardPage.getAddNewButton().click();
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
  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Update').click();
  expect(await dashboardForm.descriptionField.value()).toEqual('Test e2e Description');
  await dashboardForm.getCloseButton().click();

  // ---------
  // endregion

  // region Update dashboard properties
  // ----------------------------------

  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Update').click();
  await expect(dashboardForm.getUpdateTitle()).toBeVisible();
  await dashboardForm.nameField.fill(updateDashboardName);
  await dashboardForm.getUpdateTitle().click();
  await dashboardForm.getCloseButton().click();
  await expect(dashboardDetailsPage.getTitle(updateDashboardName)).toBeVisible();

  // ---------
  // endregion

  // region Check that dashboard have correct data
  // ---------------------------------------------

  await leftBarPage.clickOnMenu(dashboardsMenu);
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

  await leftBarPage.clickOnMenu(dashboardsMenu);
  await expect(dashboardPage.getItemFromList(duplicateDashboardName)).toBeVisible();
  await dashboardPage.getItemFromList(duplicateDashboardName).click();
  await expect(dashboardDetailsPage.getTitle(duplicateDashboardName)).toBeVisible();

  // ---------
  // endregion

  // region Delete a dashboard
  // -------------------------

  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Delete').click();
  await expect(dashboardDetailsPage.getDeleteButton()).toBeVisible();
  await dashboardDetailsPage.getDeleteButton().click();
  await expect(dashboardPage.getPageTitle()).toBeVisible();
  await expect(dashboardPage.getItemFromList(duplicateDashboardName)).toBeHidden();

  // ---------
  // endregion

  // region Export/Import dashboard
  // ------------------------------

  // From dashboard overview - export
  await leftBarPage.clickOnMenu(dashboardsMenu);
  await dashboardPage.getItemFromList(updateDashboardName).click();
  await dashboardDetailsPage.getActionsPopover().click();
  const downloadPromise = page.waitForEvent('download');
  await dashboardDetailsPage.getActionButton('Export').click();
  await page.mouse.click(10, 10); // To close action menu
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBeDefined();
  await download.saveAs(`./test-results/e2e-files/${download.suggestedFilename()}`);

  // From list page - import
  await leftBarPage.clickOnMenu(dashboardsMenu);
  await dashboardPage.getCreateMenuButton().hover();
  const fileChooserPromise = page.waitForEvent('filechooser');
  await dashboardPage.getImportButton().click();
  const fileChooser = await fileChooserPromise;
  await fileChooser.setFiles(`./test-results/e2e-files/${download.suggestedFilename()}`);
  await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();
  await expect(dashboardDetailsPage.getTitle(updateDashboardName)).toBeVisible();
  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Delete').click();
  await dashboardDetailsPage.getDeleteButton().click();

  // ---------
  // endregion

  // region Create Widget - see values - Delete Widget
  // -------------------------
  const malwareName = 'E2E dashboard - Malware - 6 months ago';
  await dashboardPage.getItemFromList(updateDashboardName).click();
  await widgetsPage.createListOfMalwaresWidget();
  await widgetsPage.getItemFromWidgetList(malwareName).click();
  await expect(malwareDetailsPage.getTitle(malwareName)).toBeVisible();

  await leftBarPage.clickOnMenu(dashboardsMenu);
  await dashboardPage.getItemFromList(updateDashboardName).click();
  await widgetsPage.getActionsWidgetsPopover().click();
  await widgetsPage.getActionButton('Delete').click();
  await widgetsPage.getDeleteButton().click();

  await widgetsPage.createTimelineOfMalwaresWidget();
  await widgetsPage.getItemFromWidgetList(malwareName).click();
  await expect(malwareDetailsPage.getTitle(malwareName)).toBeVisible();
  await widgetsPage.getIconFromWidgetTimeline().click();
  await expect(malwareDetailsPage.getTitle(malwareName)).toBeVisible();

  // ---------
  // endregion
});
