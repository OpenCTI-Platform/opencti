import { Page } from '@playwright/test';
import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import DashboardWidgetsPageModel from '../model/DashboardWidgets.pageModel';
import { addDashboard, deleteWorkspace } from '../dataForTesting/workspace.data';
import { addLabel, deleteLabel } from '../dataForTesting/label.data';
import { addReport, deleteReport } from '../dataForTesting/report.data';

// The tests below share the dashboard, labels and reports seeded in beforeAll (deleted in afterAll),
// so they run serially in one worker.
test.describe.configure({ mode: 'serial' });

/**
 * Content of the test
 * -------------------
 * Breakdown of a time series widget by the values of a field (workspace dashboards only).
 *
 * Data (API): a dashboard, a label shared by two reports and one more label for each of them.
 * The widget only selects the reports carrying the shared label, so its series do not depend on the data
 * already on the platform.
 *
 * Create a vertical bar widget on one dataset: the Filters step only announces the breakdown, the Parameters step
 * offers it (field, limit, order, "Other"), and the widget draws one series per label, "Other" last.
 * With two datasets, the breakdown controls are disabled and explained by a tooltip.
 * The fields offered never include the ones the API refuses (Contains, External references, Kill chain phases).
 */
test.describe('Dashboard widget breakdown', { tag: ['@ce', '@group1'] }, () => {
  const suffix = uuid();
  const sharedLabel = { value: `breakdown-shared-${suffix}`, id: '' };
  const labels = [
    { value: `breakdown-a-${suffix}`, id: '' },
    { value: `breakdown-b-${suffix}`, id: '' },
  ];
  const reports = [
    { name: `Breakdown report A - ${suffix}`, id: '' },
    { name: `Breakdown report B - ${suffix}`, id: '' },
  ];
  const dashboard = { name: `Dashboard - breakdown ${suffix}`, id: '' };
  const widgetTitle = `Reports by label - ${suffix}`;

  // region Data
  // -----------

  test.beforeAll(async ({ request }) => {
    const sharedLabelResponse = await addLabel(request, { value: sharedLabel.value });
    sharedLabel.id = (await sharedLabelResponse.json()).data.labelAdd.id;
    for (const [index, label] of labels.entries()) {
      const labelResponse = await addLabel(request, { value: label.value });
      label.id = (await labelResponse.json()).data.labelAdd.id;
      const reportResponse = await addReport(request, { name: reports[index].name, objectLabel: [sharedLabel.id, label.id] });
      reports[index].id = (await reportResponse.json()).data.reportAdd.id;
    }
    const dashboardResponse = await addDashboard(request, dashboard.name);
    dashboard.id = (await dashboardResponse.json()).data.workspaceAdd.id;
  });

  test.afterAll(async ({ request }) => {
    if (dashboard.id) {
      await deleteWorkspace(request, dashboard.id);
    }
    for (const report of reports.filter(({ id }) => id)) {
      await deleteReport(request, report.id);
    }
    for (const label of [...labels, sharedLabel].filter(({ id }) => id)) {
      await deleteLabel(request, label.id);
    }
  });

  // ---------
  // endregion

  const openDashboard = async (page: Page) => {
    const dashboardDetailsPage = new DashboardDetailsPage(page);
    await page.goto(`/dashboard/workspaces/dashboards/${dashboard.id}`);
    await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();
    await expect(dashboardDetailsPage.getTitle(dashboard.name)).toBeVisible();
  };

  test('Break a vertical bar widget down by label', async ({ page }) => {
    const widgetsPage = new DashboardWidgetsPageModel(page);
    await openDashboard(page);

    // region Filters step: a message, no selector
    // -------------------------------------------

    await widgetsPage.openWidgetModal();
    await widgetsPage.selectWidget('Vertical Bar');
    await widgetsPage.selectPerspective('Entities');
    await widgetsPage.filters.addFilter('Entity type', 'Report');
    await widgetsPage.filters.addFilter('Label', sharedLabel.value);
    await expect(widgetsPage.getBreakdownInfoMessage()).toBeVisible();
    await expect(widgetsPage.getBreakdownSelection()).toBeHidden();
    await expect(page.getByText('Break down by')).toBeHidden();
    await widgetsPage.validateFilters();

    // ---------
    // endregion

    // region Parameters step: field, limit, order, "Other"
    // ----------------------------------------------------

    await expect(widgetsPage.getBreakdownSelection()).toBeVisible();
    await expect(widgetsPage.breakdownField.getInput()).toBeEnabled();
    await widgetsPage.titleField.fill(widgetTitle);
    await widgetsPage.breakdownField.selectOption('Label');
    await widgetsPage.breakdownLimit.selectOption('5');
    await widgetsPage.breakdownOrder.selectOption('Highest values');
    await widgetsPage.getBreakdownOtherSwitch().check();
    await expect(widgetsPage.getBreakdownOtherSwitch()).toBeChecked();
    // The legend is off by default: the series are checked through it
    await widgetsPage.getDisplayLegendSwitch().check();
    await widgetsPage.createWidget();

    // ---------
    // endregion

    // region The widget draws one series per label, "Other" last
    // -----------------------------------------------------------

    await expect(page.getByText(widgetTitle)).toBeVisible();
    await expect(widgetsPage.getChartCanvas()).toBeVisible();
    await expect(widgetsPage.getChartLegendEntry(sharedLabel.value)).toBeVisible();
    for (const label of labels) {
      await expect(widgetsPage.getChartLegendEntry(label.value)).toBeVisible();
    }
    await expect(widgetsPage.getChartLegendEntry('Other')).toBeVisible();
    await expect(page.locator('.apexcharts-legend-text').last()).toHaveText('Other');

    // ---------
    // endregion

    // region Updating the widget keeps the breakdown
    // ----------------------------------------------

    await widgetsPage.openUpdateWidgetModal();
    // The dialog of an existing widget opens on the Filters step
    await widgetsPage.validateFilters();
    await expect(widgetsPage.breakdownField.getByText('Label')).toBeVisible();
    await expect(widgetsPage.getBreakdownOtherSwitch()).toBeChecked();

    // ---------
    // endregion
  });

  test('The breakdown controls are disabled with two datasets', async ({ page }) => {
    const widgetsPage = new DashboardWidgetsPageModel(page);
    await openDashboard(page);

    await widgetsPage.openWidgetModal();
    await widgetsPage.selectWidget('Vertical Bar');
    await widgetsPage.selectPerspective('Entities');
    await widgetsPage.filters.addFilter('Entity type', 'Report');
    await expect(widgetsPage.getBreakdownInfoMessage()).toBeVisible();
    await widgetsPage.addDataSelection();
    await expect(page.getByTestId('widget-selection-1')).toBeVisible();
    await widgetsPage.validateFilters();

    await expect(widgetsPage.getBreakdownSelection()).toBeVisible();
    await expect(widgetsPage.breakdownField.getInput()).toBeDisabled();
    // The disabled controls get no pointer events: the tooltip is carried by their wrapper
    await widgetsPage.getBreakdownSelection().locator('[tabindex="0"]').hover();
    await expect(page.getByRole('tooltip').getByText('A breakdown uses a single dataset.')).toBeVisible();
  });

  test('The fields offered exclude Contains, External references and Kill chain phases', async ({ page }) => {
    const widgetsPage = new DashboardWidgetsPageModel(page);
    await openDashboard(page);

    await widgetsPage.openWidgetModal();
    await widgetsPage.selectWidget('Vertical Bar');
    await widgetsPage.selectPerspective('Entities');
    await widgetsPage.filters.addFilter('Entity type', 'Report');
    await widgetsPage.validateFilters();

    await expect(widgetsPage.breakdownField.getInput()).toBeEnabled();
    await widgetsPage.breakdownField.getInput().click();
    const options = page.getByRole('listbox', { name: 'Break down by' });
    await expect(options.getByRole('option', { name: 'None', exact: true })).toBeVisible();
    await expect(options.getByRole('option', { name: 'Label', exact: true })).toBeVisible();
    await expect(options.getByRole('option', { name: 'Author', exact: true })).toBeVisible();
    for (const forbidden of ['Contains', 'External references', 'Kill chain phases']) {
      await expect(options.getByRole('option', { name: forbidden, exact: true })).toHaveCount(0);
    }
  });
});
