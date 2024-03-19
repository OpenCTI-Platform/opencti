import { expect, test } from '../fixtures/baseFixtures';
import FiltersPageModel from '../model/filters.pageModel';
import ReportPage from '../model/report.pageModel';

test('Add a new filter in the observables list and check the filter is still present when we come back to the page', async ({ page }) => {
  await page.goto('/dashboard/observations/observables');
  const filterUtils = new FiltersPageModel(page);
  await filterUtils.addFilterFromList('Entity type', 'Artifact');
  await expect(page.getByRole('button', { name: 'Entity type = Artifact' })).toBeVisible();
  await page.goto('/dashboard/');
  await page.goto('/dashboard/observations/observables');
  await expect(page.getByRole('button', { name: 'Entity type = Artifact' })).toBeVisible();
});

test('Add different filters with different operators', async ({ page }) => {
  await page.goto('/dashboard/observations/observables');
  const filterUtils = new FiltersUtils(page);
  await filterUtils.addFilterFromDate('Original creation date', '12', 'Lower than');
  await filterUtils.addFilterFromTextAndOperator('Value', 'Starts with', 'Empty');
  await filterUtils.addFilterFromTextAndOperator('Value', 'Starts with', 'Contains', 'content to test');
  await page.goto('/dashboard/observations/observables');
  await expect(page.getByRole('button', { name: 'Modification date < 12' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Value is empty' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Value contains : content to test' })).toBeVisible();
});

test('Check entity type background tasks filter is correct', async ({ page }) => {
  const reportPage = new ReportPage(page);
  await page.goto('/dashboard/analyses/reports');
  await reportPage.selectAllReports(); // check all the reports
  await page.getByRole('button', { name: 'delete' }).click(); // delete them via the toolbar
  await expect(page.getByText('Entity type: Report')).toBeVisible(); // the 'Entity type: Report' filter should be present
  await page.getByRole('button', { name: 'Cancel' }).click(); // don't launch the background task
});

test('Check added filter is present in background task', async ({ page }) => {
  const reportPage = new ReportPage(page);
  await page.goto('/dashboard/analyses/reports');
  const filterUtils = new FiltersUtils(page);
  await filterUtils.addFilterFromText('Modification date', '01/01/2020');
  await reportPage.selectAllReports(); // check all the reports
  await page.getByRole('button', { name: 'delete' }).click(); // delete them via the toolbar
  await page.getByRole('button', { name: 'Filters are not fully displayed' }).click(); // click in the 'filters are not fully displayed' box
  await expect(page.getByText('updated_at')).toBeVisible(); // the added filter should be present
  await page.getByRole('button', { name: 'Close' }).click(); // close the 'filters are not fully displayed panel'
  await page.getByRole('button', { name: 'Cancel' }).click(); // don't launch the background task
});
