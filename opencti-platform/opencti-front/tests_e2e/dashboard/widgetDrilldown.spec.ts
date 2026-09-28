import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import DashboardPage from '../model/dashboard.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import DashboardFormPage from '../model/form/dashboardForm.pageModel';
import DashboardWidgetsPageModel from '../model/DashboardWidgets.pageModel';
import DataTablePage from '../model/DataTable.pageModel';

/**
 * The drill-down promise, end to end: the number you clicked is the number of
 * rows you get.
 *
 * Every other test covers a piece -- the filter builders, the resolver, the
 * chart wiring. This one is the only place where the frontend resolver meets
 * the real backend aggregation, and therefore the only one that can catch a
 * boundary or a mapping error for real.
 *
 * Two surfaces are exercised, chosen because their count is readable as plain
 * DOM text rather than as an SVG label: the `number` widget (total, no upper
 * date bound) and the `distribution-list` widget (one bucket per entity type).
 * Together they cover both filter shapes the resolver can produce.
 */
test.describe.configure({ mode: 'serial' });

test('Widget drill-down opens a list holding exactly the displayed count', { tag: ['@ce', '@group1'] }, async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  const dashboardForm = new DashboardFormPage(page, 'Create dashboard');
  const dashboardDetailsPage = new DashboardDetailsPage(page);
  const widgetsPage = new DashboardWidgetsPageModel(page);
  const dataTable = new DataTablePage(page);

  const dashboardName = `Drilldown - ${uuid()}`;

  await page.goto('/dashboard/workspaces/dashboards');
  await dashboardPage.getAddNewDashboardButton().click();
  await dashboardForm.nameField.fill(dashboardName);
  await dashboardForm.getCreateButton().click();
  await dashboardPage.getItemFromList(dashboardName).click();
  await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();

  // region The `number` widget
  // --------------------------

  await widgetsPage.createNumberOfEntities();

  const numberLink = page.locator('[data-testid^="card-number-"]');
  await expect(numberLink).toBeVisible();
  const displayedTotal = Number((await numberLink.innerText()).replace(/\D/g, ''));
  // A zero would make the assertion pass without proving anything.
  expect(displayedTotal).toBeGreaterThan(0);

  await numberLink.click();
  await expect(page).toHaveURL(/\/dashboard\/.*\?filters=/);
  await expect(dataTable.getNumberElements(displayedTotal)).toBeVisible();

  await page.goBack();
  await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();

  // ---------
  // endregion

  // region The `distribution-list` widget
  // -------------------------------------

  await widgetsPage.createDistributionListOfEntities();

  const firstCount = widgetsPage.getWidgetDistributionCountLinks().first();
  await expect(firstCount).toBeVisible();
  const displayedBucket = Number((await firstCount.innerText()).replace(/\D/g, ''));
  expect(displayedBucket).toBeGreaterThan(0);

  await firstCount.click();
  await expect(page).toHaveURL(/\/dashboard\/.*\?filters=/);
  await expect(dataTable.getNumberElements(displayedBucket)).toBeVisible();

  await page.goBack();
  await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();

  // ---------
  // endregion

  await dashboardDetailsPage.delete();
  await expect(dashboardPage.getPageTitle()).toBeVisible();
});
