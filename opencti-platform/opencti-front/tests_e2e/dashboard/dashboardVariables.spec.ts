import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/secondUserFixtures';
import DashboardPage from '../model/dashboard.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import DashboardFormPage from '../model/form/dashboardForm.pageModel';
import DashboardWidgetsPageModel from '../model/DashboardWidgets.pageModel';
import DashboardVariablesPageModel from '../model/dashboardVariables.pageModel';
import AccessRestrictionPageModel from '../model/AccessRestriction.pageModel';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import { addSector, deleteSector } from '../dataForTesting/sector.data';
import { addReport, deleteReport } from '../dataForTesting/report.data';
import { addDashboard, deleteWorkspace, upsertEntityVariable } from '../dataForTesting/workspace.data';
import { REGISTER_BANNER_DISMISSED_KEY } from '../../src/utils/bannerConstants';

// The tests below share the sectors and reports seeded in beforeAll (deleted in afterAll), so they run
// serially in one worker. Consequence: if the journey test fails, the viewer test is skipped.
test.describe.configure({ mode: 'serial' });

/**
 * Content of the test
 * -------------------
 * Needs the backend started with the DASHBOARD_VARIABLES dev feature. In CI, dev features are only enabled
 * for the `@groupff` e2e group (`dev_features: '["*"]'`), hence this spec is tagged `@groupff`, not `@group1`.
 *
 * Data (API): two sectors, and one report containing each of them.
 *
 * Journey (admin):
 * Create a dashboard.
 * Create an entity variable on Sector (no restriction) whose default value is the first sector.
 * Create a widget listing reports, whose "Contains" filter is the variable, and see the report of the first sector.
 * Change the value through the chip: the widget lists the report of the second sector.
 * Reload the dashboard: the value is back (stored in the browser).
 * Delete the variable from the popover of its chip: the widget has no data anymore.
 *
 * Viewer (second user, 'can view' on the dashboard): the variables bar is not displayed.
 */
test.describe('Dashboard variables', { tag: ['@ce', '@groupff'] }, () => {
  const suffix = uuid();
  const sectors = [
    { name: `Sector A - ${suffix}`, id: '' },
    { name: `Sector B - ${suffix}`, id: '' },
  ];
  const reports = [
    { name: `Report of sector A - ${suffix}`, id: '' },
    { name: `Report of sector B - ${suffix}`, id: '' },
  ];
  const variableName = `Secteur ${suffix}`;
  const widgetTitle = `Reports of the sector - ${suffix}`;
  const dashboardName = `Dashboard - variables ${suffix}`;

  // region Data
  // -----------

  test.beforeAll(async ({ request }) => {
    for (const [index, sector] of sectors.entries()) {
      const sectorResponse = await addSector(request, { name: sector.name });
      sector.id = (await sectorResponse.json()).data.sectorAdd.id;
      const reportResponse = await addReport(request, { name: reports[index].name, objects: [sector.id] });
      reports[index].id = (await reportResponse.json()).data.reportAdd.id;
    }
  });

  test.afterAll(async ({ request }) => {
    for (const report of reports.filter(({ id }) => id)) {
      await deleteReport(request, report.id);
    }
    for (const sector of sectors.filter(({ id }) => id)) {
      await deleteSector(request, sector.id);
    }
  });

  // ---------
  // endregion

  test('Variable of a dashboard: create, use in a widget, change, reload, delete', async ({ page }) => {
    const dashboardPage = new DashboardPage(page);
    const dashboardForm = new DashboardFormPage(page, 'Create dashboard');
    const dashboardDetailsPage = new DashboardDetailsPage(page);
    const widgetsPage = new DashboardWidgetsPageModel(page);
    const variablesPage = new DashboardVariablesPageModel(page);

    // region Create the dashboard
    // ---------------------------

    await page.goto('/dashboard/workspaces/dashboards');
    await expect(dashboardPage.getPageTitle()).toBeVisible();
    await dashboardPage.getAddNewDashboardButton().click();
    await dashboardForm.nameField.fill(dashboardName);
    await dashboardForm.getCreateButton().click();
    await dashboardPage.getItemFromList(dashboardName).click();
    await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();
    await expect(dashboardDetailsPage.getTitle(dashboardName)).toBeVisible();

    // ---------
    // endregion

    // region Create the variable
    // --------------------------

    // The bar exists even with no variable yet: it carries the creation button.
    await expect(variablesPage.getBar()).toBeVisible();
    await variablesPage.createEntityVariable(variableName, 'Sector', sectors[0].name);
    await expect(variablesPage.getChipButton(variableName, sectors[0].name)).toBeVisible();

    // ---------
    // endregion

    // region Create a widget using the variable
    // -----------------------------------------

    await widgetsPage.openWidgetModal();
    await widgetsPage.selectWidget('List');
    await widgetsPage.selectPerspective('Entities');
    await widgetsPage.fillLabel('Reports');
    await widgetsPage.filters.addFilter('Entity type', 'Report');
    // The variable is offered in the value list of the filter, next to the entities (group "Variables").
    await widgetsPage.filters.addFilter('Contains', variableName);
    await widgetsPage.validateFilters();
    await widgetsPage.titleField.fill(widgetTitle);
    await widgetsPage.createWidget();

    // The default value of the variable is used: only the report of the first sector is listed.
    await expect(widgetsPage.getItemFromWidgetList(reports[0].name)).toBeVisible();
    await expect(widgetsPage.getItemFromWidgetList(reports[1].name)).toBeHidden();

    // ---------
    // endregion

    // region Change the value through the chip
    // ----------------------------------------

    await variablesPage.selectValue(variableName, sectors[0].name, sectors[1].name);
    await expect(widgetsPage.getItemFromWidgetList(reports[1].name)).toBeVisible();
    await expect(widgetsPage.getItemFromWidgetList(reports[0].name)).toBeHidden();

    // ---------
    // endregion

    // region Reload the page: the value is kept in the browser
    // --------------------------------------------------------

    // Back on the bare path: the value must come from the local storage, not from a `variables` query param.
    await page.goto(new URL(page.url()).pathname);
    await expect(dashboardDetailsPage.getTitle(dashboardName)).toBeVisible();
    await expect(variablesPage.getChipButton(variableName, sectors[1].name)).toBeVisible();
    await expect(widgetsPage.getItemFromWidgetList(reports[1].name)).toBeVisible();
    await expect(widgetsPage.getItemFromWidgetList(reports[0].name)).toBeHidden();

    // ---------
    // endregion

    // region Delete the variable
    // --------------------------

    const deleteDialog = await variablesPage.deleteVariable(variableName, sectors[1].name);
    // The widget using the variable is listed as impacted.
    await expect(deleteDialog.getByText(widgetTitle)).toBeVisible();
    await variablesPage.confirmDeletion();
    await expect(variablesPage.getChip(variableName)).toBeHidden();
    // The filter still references the deleted variable: the widget fails closed.
    await expect(page.getByText('No data has been found.', { exact: true })).toBeVisible();
    await expect(widgetsPage.getItemFromWidgetList(reports[1].name)).toBeHidden();

    // ---------
    // endregion

    // region Delete the dashboard
    // ---------------------------

    await dashboardDetailsPage.delete();
    // Being back on the list proves the delete mutation completed (deletion redirects there)
    await expect(dashboardPage.getPageTitle()).toBeVisible();
    await expect(dashboardPage.getItemFromList(dashboardName)).toBeHidden();

    // ---------
    // endregion
  });

  /**
   * The dashboard and its variable are created through the API, so this test does not use the dashboard of the
   * journey above (it still runs after it, serial mode, and is skipped if the journey fails).
   * Default setting is kept: viewers are not allowed to change the variables, hence no bar for them.
   */
  test('Variables bar is hidden for a viewer', async ({ page, request, secondUserPage }) => {
    const adminDashboards = new DashboardPage(page);
    const adminDashboardDetails = new DashboardDetailsPage(page);
    const adminVariables = new DashboardVariablesPageModel(page);
    const accessRestriction = new AccessRestrictionPageModel(page);

    const userLoginForm = new LoginFormPageModel(secondUserPage);
    const userDashboards = new DashboardPage(secondUserPage);
    const userDashboardDetails = new DashboardDetailsPage(secondUserPage);
    const userVariables = new DashboardVariablesPageModel(secondUserPage);

    const viewerDashboardName = `Dashboard - variables viewer ${suffix}`;
    const dashboardResponse = await addDashboard(request, viewerDashboardName);
    const dashboardId = (await dashboardResponse.json()).data.workspaceAdd.id;

    try {
      await upsertEntityVariable(request, dashboardId, {
        id: uuid(),
        name: variableName,
        entityTypes: ['Sector'],
        defaultValue: sectors[0].id,
      });

      // region Give a view access to Jean Michel
      // -----------------------------------------

      await page.goto('/dashboard/workspaces/dashboards');
      await expect(adminDashboards.getPageTitle()).toBeVisible();
      await adminDashboards.getItemFromList(viewerDashboardName).click();
      await expect(adminDashboardDetails.getTitle(viewerDashboardName)).toBeVisible();
      // Control: the admin does see the bar, the variable exists and is displayed.
      await expect(adminVariables.getChipButton(variableName, sectors[0].name)).toBeVisible();

      await expect(adminDashboardDetails.getActionsPopover()).toBeVisible();
      await adminDashboardDetails.getActionsPopover().click();
      await accessRestriction.openFormInMenu();
      await accessRestriction.addAccess('Jean Michel', 'can view');
      await accessRestriction.save();

      // ---------
      // endregion

      // region Sign Jean Michel in (same steps as dashboardRestriction.spec.ts)
      // -----------------------------------------------------------------------

      await secondUserPage.goto('/');
      await expect(userLoginForm.getPage()).toBeVisible();
      await secondUserPage.evaluate((key) => {
        localStorage.setItem(key, 'true');
      }, REGISTER_BANNER_DISMISSED_KEY);
      await userLoginForm.login('jean.michel@filigran.test', 'jeanmichel');
      await expect(userDashboards.getPage()).toBeVisible();

      // ---------
      // endregion

      // region The viewer opens the dashboard
      // -------------------------------------

      await secondUserPage.goto('/dashboard/workspaces/dashboards');
      await expect(userDashboards.getPageTitle()).toBeVisible();
      await userDashboards.getItemFromList(viewerDashboardName).click();
      await expect(userDashboardDetails.getDashboardDetailsPage()).toBeVisible();
      await expect(userDashboardDetails.getTitle(viewerDashboardName)).toBeVisible();
      // Read only: nothing to create or edit...
      await expect(new DashboardWidgetsPageModel(secondUserPage).getCreateWidgetButton()).toBeHidden();
      // ...and no variables bar, neither its chips nor its creation button.
      await expect(userVariables.getBar()).toBeHidden();
      await expect(userVariables.getCreateButton()).toBeHidden();
      await expect(userVariables.getChip(variableName)).toBeHidden();

      // ---------
      // endregion
    } finally {
      await deleteWorkspace(request, dashboardId);
    }
  });
});
