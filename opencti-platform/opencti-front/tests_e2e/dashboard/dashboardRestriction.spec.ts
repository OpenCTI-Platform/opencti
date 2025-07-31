/**
 * Content of the test
 * -------------------
 * Create a new dashboard as admin
 * Set a user the access can view (can view but not edit)
 * Set a user the access can edit (can view, edit, duplicate, export but not delete)
 * Set a user no access (cannot view)
 * Set a user the access can manage (can delete)
 */
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import TopMenuProfilePage from '../model/menu/topMenuProfile.pageModel';
import DashboardPage from '../model/dashboard.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import DashboardFormPage from '../model/form/dashboardForm.pageModel';
import DashboardWidgetsPageModel from '../model/DashboardWidgets.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import AccessRestrictionPageModel from '../model/AccessRestriction.pageModel';

test('Dashboard restriction access', async ({ page }) => {
  const leftBar = new LeftBarPage(page);
  const topBar = new TopMenuProfilePage(page);
  const dashboardPage = new DashboardPage(page);
  const loginForm = new LoginFormPageModel(page);
  const dashboardForm = new DashboardFormPage(page, 'Create dashboard');
  const dashboardUpdateForm = new DashboardFormPage(page, 'Update dashboard');
  const widgetsPage = new DashboardWidgetsPageModel(page);
  const dashboardDetailsPage = new DashboardDetailsPage(page);
  const accessRestriction = new AccessRestrictionPageModel(page);

  // Helper function to go to as dashboard as user jean Michel
  const goToDashboardAsJeanMichel = async (dashboardName: string) => {
    await topBar.logout();
    await loginForm.login('jean.michel@filigran.test', 'jeanmichel');
    await leftBar.clickOnMenu('Dashboards', 'Custom dashboards');
    await dashboardPage.getItemFromList(dashboardName).click();
  };

  // Helper function to go to as dashboard as user admin
  const goToDashboardAsAdmin = async (dashboardName: string) => {
    await topBar.logout();
    await loginForm.login();
    await leftBar.clickOnMenu('Dashboards', 'Custom dashboards');
    await dashboardPage.getItemFromList(dashboardName).click();
  };

  const dashboardName = `Dashboard - restriction ${new Date().getTime()}`;

  // region Prepare dashboard for tests
  // ----------------------------------
  await page.goto('/dashboard/workspaces/dashboards');
  await leftBar.open();

  // await dashboardPage.getCreateMenuButton().hover();
  await dashboardPage.getAddNewDashboardButton().click();
  await dashboardForm.nameField.fill(dashboardName);
  await dashboardForm.getCreateButton().click();

  // ---------
  // endregion

  // region Access restriction - view
  // --------------------------------

  await dashboardPage.getItemFromList(dashboardName).click();
  await dashboardDetailsPage.getActionsPopover().click();
  await accessRestriction.openFormInMenu();
  await accessRestriction.addAccess('Jean Michel', 'can view');
  await accessRestriction.save();

  await goToDashboardAsJeanMichel(dashboardName);
  await expect(widgetsPage.getCreateWidgetButton()).toBeHidden();

  // ---------
  // endregion

  // region Access restriction - edit
  // --------------------------------

  await goToDashboardAsAdmin(dashboardName);
  await dashboardDetailsPage.getActionsPopover().click();
  await accessRestriction.openFormInMenu();
  await accessRestriction.editAccess('Jean Michel', 'can edit');
  await accessRestriction.save();

  await goToDashboardAsJeanMichel(dashboardName);
  await expect(dashboardDetailsPage.getEditButton()).toBeVisible();
  await expect(dashboardDetailsPage.getExportButton()).toBeVisible();
  await dashboardDetailsPage.getActionsPopover().click();
  await expect(dashboardDetailsPage.getActionButton('Duplicate')).toBeVisible();
  await expect(dashboardDetailsPage.getActionButton('Delete')).toBeVisible();
  await page.locator('body').click();

  // Try to update
  await dashboardDetailsPage.getEditButton().click();
  await dashboardUpdateForm.nameField.fill('restriction updated');
  await dashboardUpdateForm.getCloseButton().click();
  await expect(dashboardDetailsPage.getTitle('restriction updated')).toBeVisible();
  await dashboardDetailsPage.getEditButton().click();
  await dashboardUpdateForm.nameField.fill(dashboardName);
  await dashboardUpdateForm.getCloseButton().click();
  await expect(dashboardDetailsPage.getTitle(dashboardName)).toBeVisible();

  // Try to duplicate
  await dashboardDetailsPage.getActionsPopover().click();
  await dashboardDetailsPage.getActionButton('Duplicate').click();
  await dashboardDetailsPage.getDuplicateButton().click();
  await leftBar.clickOnMenu('Dashboards', 'Custom dashboards');
  await expect(dashboardPage.getItemFromList(`${dashboardName} - copy`)).toBeVisible();
  await dashboardPage.getItemFromList(`${dashboardName} - copy`).click();
  await dashboardDetailsPage.delete();
  await page.waitForTimeout(1000);// After delete need to wait a bit

  // Try to export
  await dashboardPage.getItemFromList(dashboardName).click();
  const downloadPromise = page.waitForEvent('download');
  await dashboardDetailsPage.getExportButton().click();
  const download = await downloadPromise;
  expect(download.suggestedFilename().endsWith(`${dashboardName}.json`)).toBe(true);
  await page.mouse.click(10, 10); // To close action menu

  // ---------
  // endregion

  // region Access restriction - no access
  // -------------------------------------

  await goToDashboardAsAdmin(dashboardName);
  await dashboardDetailsPage.getActionsPopover().click();
  await accessRestriction.openFormInMenu();
  await accessRestriction.deleteAccess('Jean Michel');
  await accessRestriction.save();

  await topBar.logout();
  await loginForm.login('jean.michel@filigran.test', 'jeanmichel');
  await leftBar.clickOnMenu('Dashboards', 'Custom dashboards');
  await expect(dashboardPage.getItemFromList(dashboardName)).toBeHidden();

  // ---------
  // endregion

  // region Access restriction - manage
  // ----------------------------------

  await goToDashboardAsAdmin(dashboardName);
  await dashboardDetailsPage.getActionsPopover().click();
  await accessRestriction.openFormInMenu();
  await accessRestriction.addAccess('Jean Michel', 'can manage');
  await accessRestriction.save();
  await goToDashboardAsJeanMichel(dashboardName);
  await dashboardDetailsPage.delete();
  await page.waitForTimeout(1000);// After delete need to wait a bit
  await expect(dashboardPage.getItemFromList(dashboardName)).toBeHidden();

  // ---------
  // endregion

  // To reset the token with an admin token
  await topBar.logout();
  await loginForm.login();
  await leftBar.clickOnMenu('Dashboards', 'Custom dashboards');
  await page.context().storageState({ path: 'tests_e2e/.setup/.auth/user.json' });
});
