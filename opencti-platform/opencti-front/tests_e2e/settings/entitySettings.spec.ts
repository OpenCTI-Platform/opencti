import LeftBarPage from '../model/menu/leftBar.pageModel';
import ReportPage from '../model/report.pageModel';
import { expect, test } from '../fixtures/baseFixtures';

test('Testing content customization for Report', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  const reportPage = new ReportPage(page);

  await leftBarPage.open();

  // Checking that creation is empty
  await leftBarPage.clickOnMenu('Analyses', 'Reports');
  await reportPage.openNewReportForm();
  await expect(page.getByText(/^Content from customization$/)).toBeHidden();
  await reportPage.closeNewreport();

  // Opening customization in settings
  await leftBarPage.clickOnMenu('Settings', 'Customization');

  // Don't know why but report is the first item we can't click on directly
  await page.getByPlaceholder('Search these results...').click();
  await page.getByPlaceholder('Search these results...').fill('report');
  await page.getByPlaceholder('Search these results...').press('Enter');

  // Opening Report configuration
  await page.getByRole('link', { name: 'Report' }).click();
  await page.getByRole('button', { name: 'Content' }).click();
  // Update the default value for content
  await page.getByLabel('Editor editing area: main').fill('Content from customization');
  await page.getByRole('button', { name: 'Update' }).click();

  // Go back to the Report page
  await leftBarPage.clickOnMenu('Analyses', 'Reports');
  await reportPage.openNewReportForm();
  await expect(page.getByText(/^Content from customization$/)).toBeVisible();
  await reportPage.closeNewreport();

  // Revert changes
  await leftBarPage.clickOnMenu('Settings', 'Customization');
  await page.getByRole('link', { name: 'Report' }).click();
  await page.getByRole('button', { name: 'Content' }).click();
  await page.getByLabel('Editor editing area: main').fill('');
  await page.getByRole('button', { name: 'Update' }).click();
});
