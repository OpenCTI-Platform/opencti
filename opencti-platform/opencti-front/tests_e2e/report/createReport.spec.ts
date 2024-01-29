import { expect, test } from "../fixtures/baseFixtures";
import { login } from "../common/login";
import { ReportPage } from "../model/report.pageModel";
import { ReportDetailsPage } from "../model/reportDetails.pageModel";

  test('Create a new report page', async ({ page }) => {
    const reportPage = new ReportPage(page);
    const reportDetailsPage = new ReportDetailsPage(page);
    await login(page);
    await reportPage.goToReportPage();
    await expect(reportPage.getReportPage()).toBeVisible();
    await reportPage.addNewReport();
    await reportPage.getReportNameInput().click();
    await reportPage.getReportNameInput().fill('Test e2e');
    await reportPage.getCreateReportButton().click();
    await expect(reportPage.getReportPage()).toBeVisible();
    await page.getByRole('link', { name: 'Test e2e Unknown - admin No' }).first().click();
    await expect(reportDetailsPage.getReportDetailsPage()).toBeVisible();
  });
