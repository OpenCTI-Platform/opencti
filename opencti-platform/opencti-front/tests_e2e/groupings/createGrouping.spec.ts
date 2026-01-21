import StixCoreObjectContentTabPage from 'tests_e2e/model/StixCoreObjectContentTab.pageModel';
import { expect, test } from '../fixtures/baseFixtures';
import GroupingsPage from '../model/grouping.pageModel';
import GroupingFormPage from '../model/form/groupingForm.pageModel';
import GroupingDetailsPage from '../model/groupingDetails.pageModel';
import { format } from 'date-fns';

test('Create a new grouping', { tag: ['@ce'] }, async ({ page }) => {
  const groupingsPage = new GroupingsPage(page);
  const groupingForm = new GroupingFormPage(page);
  const groupingDetails = new GroupingDetailsPage(page);
  const stixDomainObjectContentTab = new StixCoreObjectContentTabPage(page);

  // go to groupings
  await groupingsPage.goto();
  await expect(groupingsPage.getPage()).toBeVisible();
  // add a new grouping
  await groupingsPage.addNew();
  await groupingForm.nameField.fill('Test grouping e2e');
  await groupingForm.contextSelect.selectOption('unspecified');
  await groupingForm.submit();
  // open it
  await groupingsPage.getItemFromList('Test grouping e2e').click();
  await expect(groupingDetails.getPage()).toBeVisible();
  await expect(groupingDetails.getTitle('Test grouping e2e')).toBeVisible();
  // add content
  await groupingDetails.goToTab('Content');
  await expect(stixDomainObjectContentTab.getPage()).toBeVisible();
  await stixDomainObjectContentTab.editMainContent('Main content text');
  await stixDomainObjectContentTab.addTextFile('Test file');
  await expect(page.getByText('Write something awesome...')).toBeVisible();
  const now = format(new Date(), 'MMMM d');
  await stixDomainObjectContentTab.getEditorViewButton().click();
  await stixDomainObjectContentTab.editFile(`Test file.txt ${now},`, 'Test file content text');
  await stixDomainObjectContentTab.selectMainContent();
  await expect(page.getByTestId('text-area')).toBeVisible();
  await stixDomainObjectContentTab.addHtmlFile('test file');
  await stixDomainObjectContentTab.selectFile('test file.html');
  await expect(page.getByText('No changes detected')).toBeVisible();
});
