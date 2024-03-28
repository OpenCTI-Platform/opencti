import InvestigationPage from '../model/investigation.pageModel';
import InvestigationFormPage from '../model/investigationForm.pageModel';
import { test, expect } from '../fixtures/baseFixtures';

test('deleteInvestigation', async ({ page }) => {
  // BEFORE
  const investigationPage = new InvestigationPage(page);
  const investigationForm = new InvestigationFormPage(page);

  await investigationPage.open();

  // GIVEN
  await investigationPage.openNewInvestigationForm();

  await investigationForm.fillNameInput('add investigation test');
  await investigationForm.fillDescriptionInput('add investigation test description');

  await investigationForm.getSubmitButton().click();

  // WHEN
  await investigationPage.openUpdateOrDeleteInvestigationPopover('add investigation test');
  await investigationPage.selectDeleteOptionFromInvestigationPopover();
  await investigationPage.submitDeleteInvestigation();

  // THEN
  await expect(page.getByText('add investigation test'), 'Should be deleted from the list').not.toBeVisible();
});
