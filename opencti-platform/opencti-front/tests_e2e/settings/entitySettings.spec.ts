import LeftBarPage from '../model/menu/leftBar.pageModel';
import ReportPage from '../model/report.pageModel';
import { expect, test } from '../fixtures/baseFixtures';
import SearchPageModel from '../model/search.pageModel';
import { patchEntitySetting } from '../dataForTesting/entitySetting.data';

test('Testing content customization for Report', { tag: ['@ce'] }, async ({ page, request }) => {
  // Make sure no attribute customization is set on reports, in case a previous run leaked it
  await patchEntitySetting(request, 'Report', 'attributes_configuration', '[]');

  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  const reportPage = new ReportPage(page);
  const search = new SearchPageModel(page);

  await leftBarPage.open();

  // Checking that creation is empty
  await leftBarPage.clickOnMenu('Analyses', 'Reports');
  await reportPage.openNewReportForm();
  await expect(page.getByText(/^Content from customization$/)).toBeHidden();
  await reportPage.closeNewreport();

  try {
    // Opening customization in settings
    await leftBarPage.clickOnMenu('Settings', 'Customization');

    // Don't know why but report is the first item we can't click on directly
    await search.addSearch('report');

    // Opening Report configuration
    await page.getByRole('link', { name: 'Report' }).click();
    await page.getByRole('tab', { name: 'Attributes' }).click();
    await page.getByRole('button', { name: 'Content' }).click();
    // Update the default value for content
    await page.getByLabel('Editing area: main').fill('Content from customization');
    await page.getByRole('button', { name: 'Update' }).click();

    // Go back to the Report page
    await leftBarPage.clickOnMenu('Analyses', 'Reports');
    await reportPage.openNewReportForm();
    await expect(page.getByText(/^Content from customization$/)).toBeVisible();
    await reportPage.closeNewreport();
  } finally {
    // Revert the customization through the API: an awaited call cannot be aborted by the
    // page closing at the end of the test, unlike a UI click, and it also runs when an
    // assertion failed mid-test
    await patchEntitySetting(request, 'Report', 'attributes_configuration', '[]');
  }
});
