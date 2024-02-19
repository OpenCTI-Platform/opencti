import { expect, test } from "../fixtures/baseFixtures";
import { ReportPage } from "../model/report.pageModel";
import { ReportDetailsPage } from "../model/reportDetails.pageModel";

test.skip('Create a new report page and delete it', async ({ page }) => {
  const reportPage = new ReportPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  await page.goto('/dashboard/analyses/reports');
  await reportPage.addNewReport();
  await reportPage.getReportNameInput().click();
  await reportPage.getReportNameInput().fill('Test delete report e2e');
  await reportPage.getCreateReportButton().click();
  //Issue on checked line
  await page.getByRole('link', { name: 'Test delete report Test e2e' }).first().getByRole('checkbox').check();
  await page.getByLabel('delete', { exact: true }).click();
  await page.getByRole('button', { name: 'Launch' }).click();
  await page.goto('/dashboard/analyses/reports');
  expect(page.getByRole('link', { name: 'Test delete report Test e2e' }).count()).toEqual(0);
});
