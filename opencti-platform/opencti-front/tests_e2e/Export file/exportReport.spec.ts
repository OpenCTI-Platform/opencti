import { expect, test } from '../fixtures/baseFixtures';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import FormExportPageModel from '../model/form/formExport.pageModel';
import ReportPage from '../model/report.pageModel';
import ReportFormPage from '../model/form/reportForm.pageModel';

test.skip('Add an Export in a report and check the export is present in content', async ({ page }) => {
  const reportPage = new ReportPage(page);
  const reportForm = new ReportFormPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  const formExportPage = new FormExportPageModel(page);
  await page.goto('/dashboard/analyses/reports');
  await reportPage.openNewReportForm();
  await reportForm.nameField.fill('test e2e object-markings');
  await reportPage.getCreateReportButton().click();
  await reportPage.getItemFromList('test e2e object-markings').click();
  await reportDetailsPage.getExportButton().click();
  await formExportPage.fillContentInput('Content max marking definition levels');
  await formExportPage.getMarkings('PAP:CLEAR');
  await formExportPage.fillFileInput('File marking definition levels');
  await formExportPage.getContentMarkings('PAP:CLEAR');
  await formExportPage.getCreateButton().click();
  await reportDetailsPage.getDataList();
  await expect(reportDetailsPage.getDataList()).toHaveCount(1);
});
