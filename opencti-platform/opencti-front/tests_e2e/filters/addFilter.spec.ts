import { expect, test } from '../fixtures/baseFixtures';
import FiltersUtils from '../model/filters.pageModel';
import ReportPage from '../model/report.pageModel';

test('Add a new filter in the observables list and check the filter is still present when we come back to the page', async ({ page }) => {
  await page.goto('/dashboard/observations/observables');
  const filterUtils = new FiltersUtils(page);
  await filterUtils.addFilter('Entity type', 'Artifact');
  await expect(page.getByRole('button', { name: 'Entity type = Artifact' })).toBeVisible();
  await page.goto('/dashboard/');
  await page.goto('/dashboard/observations/observables');
  await expect(page.getByRole('button', { name: 'Entity type = Artifact' })).toBeVisible();
});

test('Check entity type background tasks filter is correct', async ({ page }) => {
  const reportPage = new ReportPage(page);
  await page.goto('/dashboard/analyses/reports');
  await reportPage.selectAllReports(); // check all the reports
  await page.getByRole('button', { name: 'delete' }).click(); // delete them via the toolbar
  await expect(page.getByText('Entity type: Report')).toBeVisible(); // the 'Entity type: Report' filter should be present
  await page.getByRole('button', { name: 'Cancel' }).click(); // don't launch the background task
});
