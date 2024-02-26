import { test } from '@playwright/test';
import { LeftBarPage } from '../model/menu/leftBar.pageModel';
import { ReportPage } from '../model/report.pageModel';
import { expect } from '../fixtures/baseFixtures';

test('Testing content customization for Report', async ({ page }) => {
  await page.goto('/');
  await page.getByTestId('ChevronRightIcon').click();
  const leftBarPage = new LeftBarPage(page);
  const reportPage = new ReportPage(page);

  // Checking that creation is empty
  await leftBarPage.clickOnMenu('Analyses', 'Reports');
  await reportPage.addNewReport();
  expect(await page.getByText(/^Content from customization$/)).not.toBeVisible();
  await reportPage.closeNewreport();

  // Opening customization in settings
  await leftBarPage.clickOnMenu('Settings', 'Customization');

  // Opening Report configuration
  await page.getByRole('link', { name: 'Report' }).click();
  await page.getByRole('button', { name: 'Content' }).click();
  // Update the default value for content
  await page.getByLabel('Editor editing area: main').fill('Content from customization');
  await page.getByRole('button', { name: 'Update' }).click();

  // Go back to the Report page
  await leftBarPage.clickOnMenu('Analyses', 'Reports');
  await reportPage.addNewReport();
  expect(await page.getByText(/^Content from customization$/)).toBeVisible();
  await reportPage.closeNewreport();

  // Revert changes
  await leftBarPage.clickOnMenu('Settings', 'Customization');
  await page.getByRole('link', { name: 'Report' }).click();
  await page.getByRole('button', { name: 'Content' }).click();
  await page.getByLabel('Editor editing area: main').fill('');
  await page.getByRole('button', { name: 'Update' }).click();
});