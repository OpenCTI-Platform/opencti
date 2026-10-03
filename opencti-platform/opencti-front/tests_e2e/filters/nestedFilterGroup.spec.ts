import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import DashboardPage from '../model/dashboard.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import DashboardFormPage from '../model/form/dashboardForm.pageModel';
import DashboardWidgetsPageModel from '../model/DashboardWidgets.pageModel';

/**
 * Issue #12062 - and/or switching in the dynamic filters of dashboard queries.
 *
 * What is proven here, and nowhere else (unit tests cover the components in isolation):
 * a filter set MIXING two modes - root in 'and', nested group in 'or' - is persisted by
 * the widget mutation and restored identically after a full page reload.
 */
test('Nested filter group with its own mode survives a save and a reload', { tag: ['@ce'] }, async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  const dashboardForm = new DashboardFormPage(page, 'Create dashboard');
  const dashboardDetailsPage = new DashboardDetailsPage(page);
  const widgetsPage = new DashboardWidgetsPageModel(page);

  const dashboardName = `Dashboard nested filters - ${uuid()}`;

  // region Create the host dashboard
  // --------------------------------

  await page.goto('/dashboard/workspaces/dashboards');
  await dashboardPage.getAddNewDashboardButton().click();
  await dashboardForm.nameField.fill(dashboardName);
  await dashboardForm.getCreateButton().click();
  await dashboardPage.getItemFromList(dashboardName).click();
  await expect(dashboardDetailsPage.getTitle(dashboardName)).toBeVisible();

  // ---------
  // endregion

  // region Create a widget with a root filter AND a nested group in 'or'
  // --------------------------------------------------------------------

  await widgetsPage.openWidgetModal();
  await widgetsPage.selectWidget('List');
  await widgetsPage.selectPerspective('Entities');

  // Root level: one regular filter, so that the root and/or separator is displayed.
  await widgetsPage.filters.addFilter('Entity type', 'Malware');
  // Nested level: its own group, switched to a mode DIFFERENT from the root one.
  await widgetsPage.filters.addFilterGroup();
  await widgetsPage.filters.openGroupPanel();
  await widgetsPage.filters.switchGroupMode('OR');
  await widgetsPage.filters.addConditionInGroup('Name', 'E2E dashboard');

  // The mix is in place before saving: root 'and', nested group 'OR'.
  await expect(widgetsPage.filters.getRootModeSeparator('and')).toBeVisible();
  await widgetsPage.filters.expectGroupWithMode('OR');

  await widgetsPage.validateFilters();
  await widgetsPage.titleField.fill('Mixed and/or filters');
  await widgetsPage.createWidget();
  // The dialog closing is the only signal that the create mutation completed; reloading before
  // that races the mutation and the widget is simply not there afterwards.
  await expect(page.getByRole('dialog')).toBeHidden();

  // ---------
  // endregion

  // region Reload and check the mix has been persisted
  // --------------------------------------------------

  await page.reload();
  await expect(dashboardDetailsPage.getTitle(dashboardName)).toBeVisible();

  await widgetsPage.openUpdateWidgetModal();
  await widgetsPage.goToStep('Filters');

  // The group is still there...
  await expect(widgetsPage.filters.getGroupChip()).toBeVisible();
  await widgetsPage.filters.openGroupPanel();
  // ...still in 'or'...
  await widgetsPage.filters.expectGroupWithMode('OR');
  // ...with its condition...
  await widgetsPage.filters.expectConditionInGroup('Name', 'E2E dashboard');
  // ...while the root is still in 'and': the MIX survived the round trip.
  await expect(widgetsPage.filters.getRootModeSeparator('and')).toBeVisible();

  // ---------
  // endregion

  // region Clean up
  // ---------------

  await page.goto('/dashboard/workspaces/dashboards');
  await dashboardPage.getItemFromList(dashboardName).click();
  await dashboardDetailsPage.delete();
  // Being back on the list proves the delete mutation completed (deletion redirects there)
  await expect(dashboardPage.getPageTitle()).toBeVisible();

  // ---------
  // endregion
});
