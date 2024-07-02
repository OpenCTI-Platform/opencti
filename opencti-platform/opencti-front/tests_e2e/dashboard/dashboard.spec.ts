import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import DashboardPage from '../model/dashboard.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import DashboardFormPage from '../model/form/dashboardForm.pageModel';
import DashboardWidgetsPageModel from '../model/DashboardWidgets.pageModel';
import TopMenuProfilePage from '../model/menu/topMenuProfile.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import AccessRestrictionPageModel from '../model/AccessRestriction.pageModel';
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

  // region Interact with start and end date CTA - change value in widgets
  // -------------------------

  await leftBarPage.clickOnMenu(dashboardsMenu);
  await dashboardPage.getItemFromList(updateDashboardName).click();
  await dashboardDetailsPage.accessSelect.selectOption('None');

  await widgetsPage.createNumberOfEntities();
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '28')).toBeVisible();

  // Manipulating field "Start date"
  await dashboardDetailsPage.startDateField.fill('05/19/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '7')).toBeVisible();
  await dashboardDetailsPage.startDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.startDateField.fill('05/12/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '14')).toBeVisible();
  await dashboardDetailsPage.startDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.startDateField.fill('04/17/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '21')).toBeVisible();
  await dashboardDetailsPage.startDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.startDateField.fill('12/17/2023');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '28')).toBeVisible();
  await dashboardDetailsPage.startDateField.clear();

  // Manipulating field "End date"
  await dashboardDetailsPage.endDateField.fill('12/20/2023');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '7')).toBeVisible();
  await dashboardDetailsPage.endDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.endDateField.fill('04/19/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '14')).toBeVisible();
  await dashboardDetailsPage.endDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.endDateField.fill('05/14/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '21')).toBeVisible();
  await dashboardDetailsPage.endDateField.clear();
  await dashboardDetailsPage.getTitle(updateDashboardName).click();
  await dashboardDetailsPage.endDateField.fill('05/21/2024');
  await expect(widgetsPage.getWidgetNumberValue('Number of entities', '28')).toBeVisible();
  await dashboardDetailsPage.endDateField.clear();

  // ---------
  // endregion

  await leftBarPage.clickOnMenu(dashboardsMenu);
  await dashboardPage.getItemFromList(updateDashboardName).click();
  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Delete').click();
  await dashboardDetailsPage.getDeleteButton().click();
});

/**
 * Content of the test
 * -------------------
 * Create a new dashboard as admin
 * Set a user the access can view (can view but not edit)
 * Set a user the access can edit (can view, edit, duplicate, export but not delete)
 * Set a user no access (cannot view)
 * Set a user the access can manage (can delete)
 */
test('Dashboard restriction access', async ({ page }) => {
  const leftBar = new LeftBarPage(page);
  const topBar = new TopMenuProfilePage(page);
  const dashboardPage = new DashboardPage(page);
  const loginForm = new LoginFormPageModel(page);
  const dashboardForm = new DashboardFormPage(page);
  const widgetsPage = new DashboardWidgetsPageModel(page);
  const dashboardDetailsPage = new DashboardDetailsPage(page);
  const accessRestriction = new AccessRestrictionPageModel(page);

  // Helper function to go to as dashboard as user jean Michel
  const goToDashboardAsJeanMichel = async (dashboardName: string) => {
    await topBar.logout();
    await loginForm.login('jean.michel@filigran.test', 'jeanmichel');
    await leftBar.clickOnMenu('Dashboards');
    await dashboardPage.getItemFromList(dashboardName).click();
  };

  // Helper function to go to as dashboard as user admin
  const goToDashboardAsAdmin = async (dashboardName: string) => {
    await topBar.logout();
    await loginForm.login();
    await leftBar.clickOnMenu('Dashboards');
    await dashboardPage.getItemFromList(dashboardName).click();
  };

  // region Prepare dashboard for tests
  // ----------------------------------

  await page.goto('/dashboard/workspaces/dashboards');
  await leftBar.open();

  const dashboardName = 'Dashboard - restriction';
  await dashboardPage.getCreateMenuButton().hover();
  await dashboardPage.getAddNewButton().click();
  await dashboardForm.nameField.fill(dashboardName);
  await dashboardForm.getCreateButton().click();

  // ---------
  // endregion

  // region Access restriction - view
  // --------------------------------

  await dashboardPage.getItemFromList(dashboardName).click();
  await accessRestriction.openForm();
  await accessRestriction.addAccess('Jean Michel', 'can view');
  await accessRestriction.save();

  await goToDashboardAsJeanMichel(dashboardName);
  await expect(dashboardDetailsPage.getActionsPopover()).toBeHidden();
  await expect(widgetsPage.getCreateWidgetButton()).toBeHidden();

  // ---------
  // endregion

  // region Access restriction - edit
  // --------------------------------

  await goToDashboardAsAdmin(dashboardName);
  await accessRestriction.openForm();
  await accessRestriction.editAccess('Jean Michel', 'can edit');
  await accessRestriction.save();

  await goToDashboardAsJeanMichel(dashboardName);
  await dashboardDetailsPage.getActionsPopover().click();
  await expect(dashboardDetailsPage.getActionButton('Update')).toBeVisible();
  await expect(dashboardDetailsPage.getActionButton('Duplicate')).toBeVisible();
  await expect(dashboardDetailsPage.getActionButton('Export')).toBeVisible();
  await expect(dashboardDetailsPage.getActionButton('Delete')).toBeHidden();

  // Try to update
  await dashboardDetailsPage.getActionButton('Update').click();
  await dashboardForm.nameField.fill('restriction updated');
  await dashboardForm.getCloseButton().click();
  await expect(dashboardDetailsPage.getTitle('restriction updated')).toBeVisible();
  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Update').click();
  await dashboardForm.nameField.fill(dashboardName);
  await dashboardForm.getCloseButton().click();
  await expect(dashboardDetailsPage.getTitle(dashboardName)).toBeVisible();

  // Try to duplicate
  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Duplicate').click();
  await dashboardDetailsPage.getDuplicateButton().click();
  await leftBar.clickOnMenu('Dashboards');
  await expect(dashboardPage.getItemFromList(`${dashboardName} - copy`)).toBeVisible();
  await dashboardPage.getItemFromList(`${dashboardName} - copy`).click();
  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Delete').click();
  await dashboardDetailsPage.getDeleteButton().click();

  // Try to export
  await dashboardPage.getItemFromList(dashboardName).click();
  await dashboardDetailsPage.getActionsPopover().click();
  const downloadPromise = page.waitForEvent('download');
  await dashboardDetailsPage.getActionButton('Export').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename().endsWith(`${dashboardName}.json`)).toBe(true);
  await page.mouse.click(10, 10); // To close action menu

  // ---------
  // endregion

  // region Access restriction - no access
  // -------------------------------------

  await goToDashboardAsAdmin(dashboardName);
  await accessRestriction.openForm();
  await accessRestriction.deleteAccess('Jean Michel');
  await accessRestriction.save();

  await topBar.logout();
  await loginForm.login('jean.michel@filigran.test', 'jeanmichel');
  await leftBar.clickOnMenu('Dashboards');
  await expect(dashboardPage.getItemFromList(dashboardName)).toBeHidden();

  // ---------
  // endregion

  // region Access restriction - manage
  // ----------------------------------

  await goToDashboardAsAdmin(dashboardName);
  await accessRestriction.openForm();
  await accessRestriction.addAccess('Jean Michel', 'can manage');
  await accessRestriction.save();
  await goToDashboardAsJeanMichel(dashboardName);
  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Delete').click();
  await dashboardDetailsPage.getDeleteButton().click();
  await expect(dashboardPage.getItemFromList(dashboardName)).toBeHidden();

  // ---------
  // endregion

  // To reset the token with an admin token
  await topBar.logout();
  await loginForm.login();
  await leftBar.clickOnMenu('Dashboards');
  await page.context().storageState({ path: 'tests_e2e/.setup/.auth/user.json' });
});
