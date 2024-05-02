import { expect, test } from '../fixtures/baseFixtures';
import GroupingsPage from '../model/grouping.pageModel';
import GroupingFormPage from '../model/form/groupingForm.pageModel';
import GroupingDetailsPage from '../model/groupingDetails.pageModel';
import StixDomainObjectContentTabPage from '../model/StixDomainObjectContentTab.pageModel';

test('Create a new grouping', async ({ page }) => {
  const groupingsPage = new GroupingsPage(page);
  const groupingForm = new GroupingFormPage(page);
  const groupingDetails = new GroupingDetailsPage(page);
  const stixDomainObjectContentTab = new StixDomainObjectContentTabPage(page);

  // go to groupings
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
  // add content
  await groupingDetails.goToTab('Content');
  await expect(stixDomainObjectContentTab.getPage()).toBeVisible();
  await stixDomainObjectContentTab.editMainContent('Main content text');
  await stixDomainObjectContentTab.addFile('Test file');
  await expect(page.getByText('Write something awesome...')).toBeVisible();
  await stixDomainObjectContentTab.editFile('Test file.html', 'Test file content text');
  await stixDomainObjectContentTab.selectMainContent();
  await expect(page.getByText('Main content text')).toBeVisible();
  await stixDomainObjectContentTab.selectFile('Test file.html');
  await expect(page.getByText('Test file content text')).toBeVisible();
});
