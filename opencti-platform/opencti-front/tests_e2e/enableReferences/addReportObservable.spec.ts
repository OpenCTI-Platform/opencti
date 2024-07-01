import { expect, test } from '../fixtures/baseFixtures';
import ReportPage from '../model/report.pageModel';
import ContainerObservablesPage from '../model/containerObservables.pageModel';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import ReportFormPage from '../model/form/reportForm.pageModel';
import DashboardPage from '../model/dashboard.pageModel';
import CommitMessagePage from '../model/commitMessage.pageModel';
import ContainerAddObservablesPage from '../model/containerAddObservables.pageModel';
import RolesSettingsPage from '../model/rolesSettings.pageModel';
import RoleFormPage from '../model/form/roleForm.pageModel';
import RolePage from '../model/role.pageModel';
import GroupsSettingsPage from '../model/groupsSettings.pageModel';
import GroupPage from '../model/group.pageModel';
import GroupFormPage from '../model/form/groupForm.pageModel';
import UsersSettingsPage from '../model/usersSettings.pageModel';
import UserPage from '../model/user.pageModel';
import UserFormPage from '../model/form/userForm.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';

const noBypassUserAuthFile = 'tests_e2e/.setup/.auth/no-bypass-ref-user.json';
const noBypassUserLogin = 'noBypassReferences@user.test';
const noBypassUserPassword = 'qwerty123';
const noBypassUserName = 'NoBypassReferencesUser';
const noBypassRoleName = 'NoBypassReferencesRole';
const noBypassGroupName = 'NoBypassReferencesTestGroup';

test.describe('Create user with no references bypass capabilities', () => {
  test('Create basic user role', async ({ page }) => {
    const rolesSettingsPage = new RolesSettingsPage(page);
    const rolePage = new RolePage(page);
    const roleFormPage = new RoleFormPage(page);

    await page.goto('/dashboard/settings/accesses/roles');
    await expect(rolesSettingsPage.getSettingsPage()).toBeVisible();
    await rolesSettingsPage.getAddRoleButton().click();
    await roleFormPage.fillNameInput(noBypassRoleName);
    await roleFormPage.getCreateButton().click();
    await expect(rolesSettingsPage.getRoleInList(noBypassRoleName)).toBeVisible();
    await rolesSettingsPage.getRoleInList(noBypassRoleName).click();
    await rolePage.getEditButton().click();
    await roleFormPage.getCapabilitiesTab().click();
    await roleFormPage.getAccessKnowledgeCheckbox().click();
    await expect(roleFormPage.getAccessKnowledgeCheckbox()).toBeChecked();
    await roleFormPage.getCreateUpdateKnowledgeCheckbox().click();
    await expect(roleFormPage.getCreateUpdateKnowledgeCheckbox()).toBeChecked();
    await roleFormPage.getManageCustomizationCheckbox().click();
    await expect(roleFormPage.getManageCustomizationCheckbox()).toBeChecked();
  });

  test('Create basic user group', async ({ page }) => {
    const groupsSettingsPage = new GroupsSettingsPage(page);
    const groupPage = new GroupPage(page);
    const groupFormPage = new GroupFormPage(page);

    await page.goto('/dashboard/settings/accesses/groups');
    await expect(groupsSettingsPage.getSettingsPage()).toBeVisible();
    await groupsSettingsPage.getAddGroupButton().click();
    await groupFormPage.fillNameInput(noBypassGroupName);
    await groupFormPage.getCreateButton().click();
    await expect(groupsSettingsPage.getGroupInList(noBypassGroupName)).toBeVisible();
    await groupsSettingsPage.getGroupInList(noBypassGroupName).click();
    await groupPage.getEditButton().click();
    await groupFormPage.getRolesTab().click();
    await groupFormPage.getSpecificRuleCheckbox(noBypassRoleName).click();
    await expect(groupFormPage.getSpecificRuleCheckbox(noBypassRoleName)).toBeChecked();
  });

  test('Create basic user', async ({ page }) => {
    const usersSettingsPage = new UsersSettingsPage(page);
    const userPage = new UserPage(page);
    const userFormPage = new UserFormPage(page);

    await page.goto('/dashboard/settings/accesses/users');
    await expect(usersSettingsPage.getSettingsPage()).toBeVisible();
    await usersSettingsPage.getAddUserButton().click();
    await userFormPage.fillNameInput(noBypassUserName);
    await userFormPage.fillEmailInput(noBypassUserLogin);
    await userFormPage.fillPasswordInput(noBypassUserPassword);
    await userFormPage.fillPasswordConfirmationInput(noBypassUserPassword);
    await userFormPage.getCreateButton().click();
    await expect(usersSettingsPage.getUserInList(noBypassUserName)).toBeVisible();
    await usersSettingsPage.getUserInList(noBypassUserName).click();
    await userPage.getEditButton().click();
    await userFormPage.getGroupsTab().click();
    await userFormPage.getSpecificGroupCheckbox(noBypassGroupName).click();
    await expect(userFormPage.getSpecificGroupCheckbox(noBypassGroupName)).toBeChecked();
    await userFormPage.getSpecificGroupCheckbox('Default (Max Confidence').click();
    await expect(userFormPage.getSpecificGroupCheckbox('Default (Max Confidence')).not.toBeChecked();
  });
});

test.describe('Authenticate no bypass user', () => {
  test.use({ storageState: { cookies: [], origins: [] } });
  test('Authenticate basic user', async ({ page }) => {
    const dashboardPage = new DashboardPage(page);
    const loginPage = new LoginFormPageModel(page);

    await page.goto('/');
    await expect(loginPage.getPage()).toBeVisible();
    await loginPage.login(noBypassUserLogin, noBypassUserPassword);
    await expect(dashboardPage.getPage()).toBeVisible();
    await page.context().storageState({ path: noBypassUserAuthFile });
  });
});

test('Add and remove observable from Observables tab of a Report as Admin user', async ({ page }) => {
  const reportPage = new ReportPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  const reportForm = new ReportFormPage(page);
  const containerObservablesPage = new ContainerObservablesPage(page);
  const containerAddObservablesPage = new ContainerAddObservablesPage(page);
  const leftBarPage = new LeftBarPage(page);

  // Create a report and check that adding an observable is possible
  await page.goto('/dashboard/analyses/reports');

  await reportPage.openNewReportForm();
  await reportForm.nameField.fill('Test add observable e2e');
  await reportPage.getCreateReportButton().click();
  await reportPage.getItemFromList('Test add observable e2e').click();
  await expect(reportDetailsPage.getReportDetailsPage()).toBeVisible();
  await reportDetailsPage.goToObservablesTab();
  await expect(containerObservablesPage.getContainerObservablesPage()).toBeVisible();
  await containerObservablesPage.getAddObservableListButton().click();
  await containerAddObservablesPage.createNewIPV4Observable('8.8.8.8');
  await expect(containerAddObservablesPage.getObservable('IPv4 address 8.8.8.8')).toBeVisible();
  await containerAddObservablesPage.getObservable('IPv4 address 8.8.8.8').click();
  await containerAddObservablesPage.getCloseObservablesListButton().click();
  await expect(containerObservablesPage.getObservableInContainer('IPv4 address 8.8.8.8')).toBeVisible();

  // Enable report references and check that removing observable is still possible as admin user
  await leftBarPage.clickOnMenu('Settings', 'Customization');
  await page.getByPlaceholder('Search these results...').click();
  await page.getByPlaceholder('Search these results...').fill('report');
  await page.getByPlaceholder('Search these results...').press('Enter');
  await page.getByRole('link', { name: 'Report' }).click();
  await page.locator('span').filter({ hasText: 'Enforce references' }).click();

  await leftBarPage.clickOnMenu('Analyses', 'Reports');
  await reportPage.getItemFromList('Test add observable e2e').click();
  await reportDetailsPage.goToObservablesTab();
  await expect(containerObservablesPage.getContainerObservablesPage()).toBeVisible();
  await containerObservablesPage.getAddObservableListButton().click();
  await expect(containerAddObservablesPage.getObservable('IPv4 address 8.8.8.8')).toBeVisible();
  await containerAddObservablesPage.getObservable('IPv4 address 8.8.8.8').click();
  await containerAddObservablesPage.getCloseObservablesListButton().click();
  await expect(containerObservablesPage.getObservableInContainer('IPv4 address 8.8.8.8')).toBeHidden();

  // Clean up report "enable references" configuration
  await leftBarPage.clickOnMenu('Settings', 'Customization');
  await page.getByRole('link', { name: 'Report' }).click();
  await page.locator('span').filter({ hasText: 'Enforce references' }).click();
});

test.describe('Add and remove observable from Observables tab of a Report as noBypass user', () => {
  test.use({ storageState: noBypassUserAuthFile });
  test('Run test as noBypass user', async ({ page }) => {
    const reportPage = new ReportPage(page);
    const reportDetailsPage = new ReportDetailsPage(page);
    const reportForm = new ReportFormPage(page);
    const containerObservablesPage = new ContainerObservablesPage(page);
    const containerAddObservablesPage = new ContainerAddObservablesPage(page);
    const commitMessagePage = new CommitMessagePage(page);
    const leftBarPage = new LeftBarPage(page);

    // Create a report and check that adding an observable is possible
    await page.goto('/dashboard/analyses/reports');
    await page.getByTestId('ChevronRightIcon').click();
    await reportPage.openNewReportForm();
    await reportForm.nameField.fill('Test add observable e2e 2');
    await reportPage.getCreateReportButton().click();
    await reportPage.getItemFromList('Test add observable e2e 2').click();
    await expect(reportDetailsPage.getReportDetailsPage()).toBeVisible();
    await reportDetailsPage.goToObservablesTab();
    await expect(containerObservablesPage.getContainerObservablesPage()).toBeVisible();
    await containerObservablesPage.getAddObservableListButton().click();
    await containerAddObservablesPage.createNewIPV4Observable('9.9.9.9');
    await expect(containerAddObservablesPage.getObservable('IPv4 address 9.9.9.9')).toBeVisible();
    await containerAddObservablesPage.getObservable('IPv4 address 9.9.9.9').click();
    await containerAddObservablesPage.getCloseObservablesListButton().click();
    await expect(containerObservablesPage.getObservableInContainer('IPv4 address 9.9.9.9')).toBeVisible();

    // Enable report references and check that removing observable asks for an external reference
    await leftBarPage.clickOnMenu('Settings', 'Customization');
    await page.getByPlaceholder('Search these results...').click();
    await page.getByPlaceholder('Search these results...').fill('report');
    await page.getByPlaceholder('Search these results...').press('Enter');
    await page.getByRole('link', { name: 'Report' }).click();
    await page.locator('span').filter({ hasText: 'Enforce references' }).click();

    await leftBarPage.clickOnMenu('Analyses', 'Reports');
    await reportPage.getItemFromList('Test add observable e2e 2').click();
    await reportDetailsPage.goToObservablesTab();
    await expect(containerObservablesPage.getContainerObservablesPage()).toBeVisible();
    await containerObservablesPage.getAddObservableListButton().click();
    await expect(containerAddObservablesPage.getObservable('IPv4 address 9.9.9.9')).toBeVisible();
    await containerAddObservablesPage.getObservable('IPv4 address 9.9.9.9').click();
    await expect(commitMessagePage.getPage()).toBeVisible();
    await commitMessagePage.getAddNewReferenceButton().click();
    await commitMessagePage.fillNewReferenceSourceNameInput('SourceTest');
    await commitMessagePage.fillNewReferenceExternalIDInput('SourceTest');
    await commitMessagePage.getNewReferenceCreateButton().click();
    await commitMessagePage.getValidateButton().click();
    await containerAddObservablesPage.getCloseObservablesListButton().click();
    await expect(containerObservablesPage.getObservableInContainer('IPv4 address 9.9.9.9')).toBeHidden();

    // Clean up report "enable references" configuration
    await leftBarPage.clickOnMenu('Settings', 'Customization');
    await page.getByRole('link', { name: 'Report' }).click();
    await page.locator('span').filter({ hasText: 'Enforce references' }).click();
  });
});
