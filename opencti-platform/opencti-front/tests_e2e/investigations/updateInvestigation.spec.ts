import InvestigationsPage from 'tests_e2e/model/investigations.pageModel';
import { expect, test } from '../fixtures/baseFixtures';
import InvestigationDetailsPage from '../model/investigationDetails.pageModel';
import InvestigationsFormPage from '../model/form/investigationsForm.pageModel';

test('Create a new dashboard page and test update', async ({ page }) => {
  const investigationsPage = new InvestigationsPage(page);
  const investigationDetailsPage = new InvestigationDetailsPage(page);
  const investigationsForm = new InvestigationsFormPage(page, 'Create investigation');
  const investigationsUpdateForm = new InvestigationsFormPage(page, 'Update investigation');
  await page.goto('/dashboard/workspaces/investigations');
  await investigationsPage.addNewInvestigation().click();
  await investigationsForm.nameField.fill('Test Update e2e');
  await investigationsPage.getCreateInvestigationButton().click();
  await investigationsPage.getItemFromList('Test Update e2e').click();
  await investigationDetailsPage.openPopUpButton().click();
  await investigationDetailsPage.getEditButton().click();
  await investigationsUpdateForm.nameField.fill('Modification Test Update e2e');
  await investigationsUpdateForm.getCloseButton().click();
  await expect(investigationDetailsPage.getTitle('Modification Test Update e2e')).toBeVisible();
});
