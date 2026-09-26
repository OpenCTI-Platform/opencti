/**
 * Content of the test
 * -------------------
 * Create a new dashboard as admin
 * Set a user the access can view (can view but not edit)
 * Set a user the access can edit (can view, edit, duplicate, export but not delete)
 * Set a user no access (cannot view)
 * Set a user the access can manage (can delete)
 *
 * The admin drives the default page, Jean Michel a second browser context: the two
 * sessions live side by side instead of taking turns through the login screen.
 */
import { expect, test } from '../fixtures/secondUserFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import DashboardPage from '../model/dashboard.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import DashboardFormPage from '../model/form/dashboardForm.pageModel';
import DashboardWidgetsPageModel from '../model/DashboardWidgets.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import AccessRestrictionPageModel from '../model/AccessRestriction.pageModel';
import { REGISTER_BANNER_DISMISSED_KEY } from '../../src/utils/bannerConstants';

test('Dashboard restriction access', { tag: ['@ce', '@group1'] }, async ({ page, secondUserPage }) => {
  const adminLeftBar = new LeftBarPage(page);
  const adminDashboards = new DashboardPage(page);
  const adminDashboardDetails = new DashboardDetailsPage(page);
  const adminDashboardForm = new DashboardFormPage(page, 'Create dashboard');
  const accessRestriction = new AccessRestrictionPageModel(page);

  const userLoginForm = new LoginFormPageModel(secondUserPage);
  const userLeftBar = new LeftBarPage(secondUserPage);
  const userDashboards = new DashboardPage(secondUserPage);
  const userDashboardDetails = new DashboardDetailsPage(secondUserPage);
  const userDashboardUpdateForm = new DashboardFormPage(secondUserPage, 'Update dashboard');
  const userWidgets = new DashboardWidgetsPageModel(secondUserPage);

  const dashboardName = `Dashboard - restriction ${new Date().getTime()}`;

  const openDashboardListAsJeanMichel = async () => {
    await secondUserPage.goto('/dashboard/workspaces/dashboards');
    await expect(userDashboards.getPageTitle()).toBeVisible();
  };

  const openDashboardAsJeanMichel = async () => {
    await openDashboardListAsJeanMichel();
    await userDashboards.getItemFromList(dashboardName).click();
  };

  const openAccessRestrictionAsAdmin = async () => {
    // The popover is out of reach of the label query while the previous drawer finishes closing.
    await expect(adminDashboardDetails.getActionsPopover()).toBeVisible();
    await adminDashboardDetails.getActionsPopover().click();
    await accessRestriction.openFormInMenu();
  };

  // region Sign Jean Michel in, once for the whole test
  // --------------------------------------------------

  await secondUserPage.goto('/');
  await expect(userLoginForm.getPage()).toBeVisible();
  // Same reason as in auth.setup.ts: the banner button is fixed-position and intercepts clicks.
  await secondUserPage.evaluate((key) => {
    localStorage.setItem(key, 'true');
  }, REGISTER_BANNER_DISMISSED_KEY);
  await userLoginForm.login('jean.michel@filigran.test', 'jeanmichel');
  await expect(userDashboards.getPage()).toBeVisible();

  // ---------
  // endregion

  // region Prepare dashboard for tests
  // ----------------------------------

  await page.goto('/dashboard/workspaces/dashboards');
  await expect(adminDashboards.getPageTitle()).toBeVisible();
  await adminLeftBar.open();

  await adminDashboards.getAddNewDashboardButton().click();
  await adminDashboardForm.nameField.fill(dashboardName);
  await adminDashboardForm.getCreateButton().click();

  // The admin opens the dashboard once and edits the restrictions from that page until the end.
  await adminDashboards.getItemFromList(dashboardName).click();

  // ---------
  // endregion

  // region Access restriction - view
  // --------------------------------

  await openAccessRestrictionAsAdmin();
  await accessRestriction.addAccess('Jean Michel', 'can view');
  await accessRestriction.save();

  await openDashboardAsJeanMichel();
  await expect(userWidgets.getCreateWidgetButton()).toBeHidden();

  // ---------
  // endregion

  // region Access restriction - edit
  // --------------------------------

  await openAccessRestrictionAsAdmin();
  await accessRestriction.editAccess('Jean Michel', 'can edit');
  await accessRestriction.save();

  await openDashboardAsJeanMichel();
  await expect(userDashboardDetails.getEditButton()).toBeVisible();
  await expect(userDashboardDetails.getExportButton()).toBeVisible();
  await userDashboardDetails.getActionsPopover().click();
  await expect(userDashboardDetails.getActionButton('Duplicate')).toBeVisible();
  await expect(userDashboardDetails.getActionButton('Delete')).toBeVisible();
  await secondUserPage.locator('body').click();

  // Try to update
  await userDashboardDetails.getEditButton().click();
  await userDashboardUpdateForm.nameField.fill('restriction updated');
  await userDashboardUpdateForm.getCloseButton().click();
  await expect(userDashboardDetails.getTitle('restriction updated')).toBeVisible();
  await userDashboardDetails.getEditButton().click();
  await userDashboardUpdateForm.nameField.fill(dashboardName);
  await userDashboardUpdateForm.getCloseButton().click();
  await expect(userDashboardDetails.getTitle(dashboardName)).toBeVisible();

  // Try to duplicate
  await userDashboardDetails.getActionsPopover().click();
  await userDashboardDetails.getActionButton('Duplicate').click();
  await userDashboardDetails.getDuplicateButton().click();
  await userLeftBar.clickOnMenu('Dashboards', 'Custom dashboards');
  await expect(userDashboards.getItemFromList(`${dashboardName} - copy`)).toBeVisible();
  await userDashboards.getItemFromList(`${dashboardName} - copy`).click();
  await userDashboardDetails.delete();
  // Being back on the list proves the delete mutation completed (deletion redirects there)
  await expect(userDashboards.getPageTitle()).toBeVisible();

  // Try to export
  await userDashboards.getItemFromList(dashboardName).click();
  const downloadPromise = secondUserPage.waitForEvent('download');
  await userDashboardDetails.getExportButton().click();
  const download = await downloadPromise;
  expect(download.suggestedFilename().endsWith(`${dashboardName}.json`)).toBe(true);
  await secondUserPage.mouse.click(10, 10); // To close action menu

  // ---------
  // endregion

  // region Access restriction - no access
  // -------------------------------------

  await openAccessRestrictionAsAdmin();
  await accessRestriction.deleteAccess('Jean Michel');
  await accessRestriction.save();

  await openDashboardListAsJeanMichel();
  await expect(userDashboards.getItemFromList(dashboardName)).toBeHidden();

  // ---------
  // endregion

  // region Access restriction - manage
  // ----------------------------------

  await openAccessRestrictionAsAdmin();
  await accessRestriction.addAccess('Jean Michel', 'can manage');
  await accessRestriction.save();

  await openDashboardAsJeanMichel();
  await userDashboardDetails.delete();
  // Being back on the list proves the delete mutation completed (deletion redirects there)
  await expect(userDashboards.getPageTitle()).toBeVisible();
  await expect(userDashboards.getItemFromList(dashboardName)).toBeHidden();

  // ---------
  // endregion
});
