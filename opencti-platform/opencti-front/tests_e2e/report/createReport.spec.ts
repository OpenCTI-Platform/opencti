import { expect, test } from '../fixtures/baseFixtures';
import { ReportPage } from '../model/report.pageModel';
import { ReportDetailsPage } from '../model/reportDetails.pageModel';
import { ReportFormPage } from '../model/reportForm.pageModel';
import * as path from 'path';

test('Create a new report page', async ({ page }) => {
  const reportPage = new ReportPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  const reportForm = new ReportFormPage(page);
  await page.goto('/dashboard/analyses/reports');
  await reportPage.addNewReport();
  await reportForm.fillNameInput('Test e2e');
  await reportPage.getCreateReportButton().click();
  await reportPage.getItemFromList('Test e2e').click();
  await expect(reportDetailsPage.getReportDetailsPage()).toBeVisible();
});

test('Create a new report with associated file', async ({ page }) => {
  const reportPage = new ReportPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  const reportForm = new ReportFormPage(page);
  await page.goto('/dashboard/analyses/reports');
  await reportPage.addNewReport();
  await reportForm.fillNameInput('Test e2e with file');
  const fileChooserPromise = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: 'Select your file', exact: true }).click();
  const fileChooser = await fileChooserPromise;
  await fileChooser.setFiles(path.join(__dirname, 'createReport.spec.ts'));
  await reportPage.getCreateReportButton().click();
  await reportPage.getItemFromList('Test e2e with file').click();
  await expect(reportDetailsPage.getReportDetailsPage()).toBeVisible();
  await page.getByRole('tab', { name: 'Data' }).click();
  await expect(page.getByRole('button', { name: 'createReport.spec.ts Launch' })).toBeVisible()
});
