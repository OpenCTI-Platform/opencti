import { expect, test } from '../fixtures/baseFixtures';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import FormExportPageModel from '../model/formExport.pageModel';

test('Add an Export in a report and check the export is present in content', async ({ page }) => {
  const reportDetailsPage = new ReportDetailsPage(page);
  const formExportPage = new FormExportPageModel(page);
  await page.goto('/dashboard/analyses/reports');
  await reportDetailsPage.getOneReport('report object-markings').click();
  await reportDetailsPage.getExportButton().click();
  // await formExportPage.fillFormatInput('application/pdf');
  await formExportPage.fillContentInput('Content max marking definition levels');
  await formExportPage.getMarkings('PAP:CLEAR');
  await formExportPage.fillFileInput('File marking definition levels');
  await formExportPage.getContentMarkings('PAP:CLEAR');
  await formExportPage.getCreateButton().click();
  await page.waitForTimeout(50000);
  await expect(reportDetailsPage.getDataList(':has-text("PAP:CLEAR")')).toBeVisible();
  // await expect(reportDetailsPage.getNewFile()).toBeVisible();
  // await expect(reportDetailsPage.getPopAlert('Export successfully started')).toBeVisible({ timeout: 50000 });
});
