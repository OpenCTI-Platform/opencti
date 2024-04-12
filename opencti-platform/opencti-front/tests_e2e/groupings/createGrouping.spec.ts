import { expect, test } from '../fixtures/baseFixtures';
import GroupingsPage from '../model/grouping.pageModel';
import GroupingFormPage from '../model/groupingForm.pageModel';
import GroupingDetailsPage from '../model/groupingDetails.pageModel';

test('Create a new grouping', async ({ page }) => {
  // go to groupings
  const groupingsPage = new GroupingsPage(page);
  const groupingForm = new GroupingFormPage(page);
  const groupingDetails = new GroupingDetailsPage(page);
  await page.goto('/dashboard/analyses/groupings');
  await expect(groupingsPage.getPage()).toBeVisible();
  // add a new grouping
  await groupingsPage.addNew();
  await groupingForm.fillNameInput('Test grouping e2e');
  await groupingForm.selectContextLabel('A set of STIX content contextually related but without any precise');
  await groupingForm.submit();
  // open it
  await groupingsPage.getItemFromList('Test grouping e2e').click();
  await expect(groupingDetails.getGroupingDetailsPage()).toBeVisible();
  await expect(groupingDetails.getTitle('Test grouping e2e')).toBeVisible();
});
