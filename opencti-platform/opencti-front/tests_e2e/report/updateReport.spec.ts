import { expect, test } from "../fixtures/baseFixtures";
import { ReportPage } from "../model/report.pageModel";
import { ReportDetailsPage } from "../model/reportDetails.pageModel";
import { ReportFormPage } from "../model/reportForm.pageModel";

test('Create a new report page and test update', async ({ page }) => {
  const reportPage = new ReportPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  const reportForm = new ReportFormPage(page);
  await page.goto('/dashboard/analyses/reports');
  await reportPage.addNewReport();
  await reportForm.fillNameInput('Test Update e2e');
  await reportPage.getCreateReportButton().click();
  await reportPage.getItemFromList( 'Test Update e2e Unknown - admin No' ).click();
  await reportDetailsPage.getEditButton().click();
  await reportForm.fillNameInput('Modification Test Update e2e');
  await reportForm.getCloseButton().click();
  await expect(reportDetailsPage.getTitle('Modification Test Update e2e')).toBeVisible()
});
