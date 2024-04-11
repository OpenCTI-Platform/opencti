// TODO: uncomment when feature flag is removed, since e2e backend tests currently use default feature flag config
// import { expect, test } from '../fixtures/baseFixtures';
// import ReportPage from '../model/report.pageModel';
// import ReportFormPage from '../model/reportForm.pageModel';
// import LeftBarPage from '../model/menu/leftBar.pageModel';
// import TrashPage from '../model/trash.pageModel';
//
// test('Create a trash entry', async ({ page }) => {
//   const reportPage = new ReportPage(page);
//   const reportForm = new ReportFormPage(page);
//   const trashPage = new TrashPage(page);
//   const leftBarPage = new LeftBarPage(page);
//   const reportName = 'Test e2e trash entry';
//
//   // Create and delete a report
//   await page.goto('/dashboard/analyses/reports');
//   await page.getByTestId('ChevronRightIcon').click();
//   await reportPage.addNewReport();
//   await reportForm.fillNameInput(reportName);
//   await reportPage.getCreateReportButton().click();
//   await page.getByRole('link', { name: reportName }).first().getByRole('checkbox').click();
//   await page.getByLabel('delete', { exact: true }).click();
//   await page.getByRole('button', { name: 'Launch' }).click();
//   await page.waitForTimeout(3000);
//
//   // Go to trash and make sure that it contains deleted report
//   await leftBarPage.clickOnMenu('Trash');
//   await expect(trashPage.getPage()).toBeVisible();
//   await expect(trashPage.getPage()).toContainText(reportName);
// });
