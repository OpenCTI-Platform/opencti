import { expect, test } from "../fixtures/baseFixtures";
import { ReportPage } from "../model/report.pageModel";
import { ReportDetailsPage } from "../model/reportDetails.pageModel";
import { ReportFormPage } from "../model/reportForm.pageModel";

  test('Create a new report page', async ({ page }) => {
    const reportPage = new ReportPage(page);
    const reportDetailsPage = new ReportDetailsPage(page);
    const reportForm = new ReportFormPage(page);
    await page.goto('/dashboard/analyses/reports');
    await reportPage.addNewReport();
    await reportForm.fillNameInput('Test e2e');
    await reportPage.getCreateReportButton().click();
    await reportPage.getItemFromList( 'Test e2e Unknown - admin No' ).click();
    await expect(reportDetailsPage.getReportDetailsPage()).toBeVisible();
  });
