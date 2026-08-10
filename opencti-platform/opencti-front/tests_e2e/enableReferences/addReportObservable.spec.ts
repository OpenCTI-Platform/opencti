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
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import { patchEntitySetting } from '../dataForTesting/entitySetting.data';

const noBypassUserAuthFile = 'tests_e2e/.setup/.auth/no-bypass-ref-user.json';
const nowTime = `${new Date().getTime()}`;

const noBypassUserLogin = `${nowTime}+noBypassReferences@user.test`;
const noBypassUserPassword = 'qwerty123';
const noBypassUserName = `NoBypassReferencesUser ${nowTime}`;
const noBypassRoleName = `NoBypassReferencesRole ${nowTime}`;
const noBypassGroupName = `NoBypassReferencesTestGroup ${nowTime}`;

test.describe('Create user with no references bypass capabilities', { tag: ['@ce'] }, () => {
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

test.describe('Authenticate no bypass user', { tag: ['@ce'] }, () => {
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

test('Add and remove observable from Observables tab of a Report as Admin user', { tag: ['@ce'] }, async ({ page, request }) => {
  const reportPage = new ReportPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  const reportForm = new ReportFormPage(page);
  const containerObservablesPage = new ContainerObservablesPage(page);
  const containerAddObservablesPage = new ContainerAddObservablesPage(page);

  // Make sure references are not enforced on reports, in case a previous run leaked the setting
  await patchEntitySetting(request, 'Report', 'enforce_reference', false);

  // Create a report and check that adding an observable is possible
  await page.goto('/dashboard/analyses/reports');

  const reportName = `Test add observable e2e ${nowTime}`;

  await reportPage.openNewReportForm();
  await reportForm.nameField.fill(reportName);
  await reportPage.getCreateReportButton().click();
  await reportPage.getItemFromList(reportName).click();
  await expect(reportDetailsPage.getPage()).toBeVisible();
  await reportDetailsPage.tabs.goToObservablesTab();
  await expect(containerObservablesPage.getPage()).toBeVisible();
  await containerObservablesPage.getAddObservableListButton().click();
  await containerAddObservablesPage.createNewIPV4Observable('8.8.8.8');
  await expect(containerAddObservablesPage.getObservable('IPv4 address 8.8.8.8')).toBeVisible();
  await containerAddObservablesPage.getObservable('IPv4 address 8.8.8.8').click();
  await containerAddObservablesPage.getCloseObservablesListButton().click();
  await expect(containerObservablesPage.getObservableInContainer('IPv4 address 8.8.8.8')).toBeVisible();

  try {
    // Enable report references and check that removing observable is still possible as admin user
    await patchEntitySetting(request, 'Report', 'enforce_reference', true);
    // Entity settings are fetched on full page load only, so reload instead of navigating from the menu
    await page.goto('/dashboard/analyses/reports');

    await reportPage.getItemFromList(reportName).click();
    await reportDetailsPage.tabs.goToObservablesTab();
    await expect(containerObservablesPage.getPage()).toBeVisible();
    await containerObservablesPage.getAddObservableListButton().click();
    await expect(containerAddObservablesPage.getObservable('IPv4 address 8.8.8.8')).toBeVisible();
    await containerAddObservablesPage.getObservable('IPv4 address 8.8.8.8').click();
    await containerAddObservablesPage.getCloseObservablesListButton().click();
    await expect(containerObservablesPage.getObservableInContainer('IPv4 address 8.8.8.8')).toBeHidden();
  } finally {
    // Clean up report "enforce references" configuration through the API: an awaited call
    // cannot be aborted by the page closing at the end of the test, unlike a UI click
    await patchEntitySetting(request, 'Report', 'enforce_reference', false);
  }
});

test.describe('Add and remove observable from Observables tab of a Report as noBypass user', { tag: ['@ce'] }, () => {
  test.use({ storageState: noBypassUserAuthFile });
  test('Run test as noBypass user', async ({ page, request }) => {
    const reportPage = new ReportPage(page);
    const reportDetailsPage = new ReportDetailsPage(page);
    const reportForm = new ReportFormPage(page);
    const containerObservablesPage = new ContainerObservablesPage(page);
    const containerAddObservablesPage = new ContainerAddObservablesPage(page);
    const commitMessagePage = new CommitMessagePage(page);

    // Make sure references are not enforced on reports, in case a previous run leaked the setting
    await patchEntitySetting(request, 'Report', 'enforce_reference', false);

    // Create a report and check that adding an observable is possible
    const reportName = `Test add observable e2e 2 ${nowTime}`;
    await reportPage.goto();
    // Was `getByTestId('ChevronRightIcon')`: the rail's expand affordance used
    // to be a raw MUI icon. The design-system rail exposes a named control,
    // so this goes through the page object like every other rail interaction.
    await leftBarPage.open();
    await reportPage.openNewReportForm();
    await reportForm.nameField.fill(reportName);
    await reportPage.getCreateReportButton().click();
    await reportPage.getItemFromList(reportName).click();
    await expect(reportDetailsPage.getPage()).toBeVisible();
    await reportDetailsPage.tabs.goToObservablesTab();
    await expect(containerObservablesPage.getPage()).toBeVisible();
    await containerObservablesPage.getAddObservableListButton().click();
    await containerAddObservablesPage.createNewIPV4Observable('9.9.9.9');
    await expect(containerAddObservablesPage.getObservable('IPv4 address 9.9.9.9')).toBeVisible();
    await containerAddObservablesPage.getObservable('IPv4 address 9.9.9.9').click();
    await containerAddObservablesPage.getCloseObservablesListButton().click();
    await expect(containerObservablesPage.getObservableInContainer('IPv4 address 9.9.9.9')).toBeVisible();

    try {
      // Enable report references and check that removing observable asks for an external reference
      await patchEntitySetting(request, 'Report', 'enforce_reference', true);
      // Entity settings are fetched on full page load only, so reload instead of navigating from the menu
      await reportPage.goto();

      await reportPage.getItemFromList(reportName).click();
      await reportDetailsPage.tabs.goToObservablesTab();
      await expect(containerObservablesPage.getPage()).toBeVisible();
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
    } finally {
      // Clean up report "enforce references" configuration through the API: an awaited call
      // cannot be aborted by the page closing at the end of the test, unlike a UI click
      await patchEntitySetting(request, 'Report', 'enforce_reference', false);
    }
  });
});
