import { expect, test } from '../fixtures/baseFixtures';
import InvestigationDetailsPage from '../model/investigationDetails.pageModel';
import InvestigationsFormPage from '../model/form/investigationsForm.pageModel';
import InvestigationsPage from '../model/investigations.pageModel';

test('Create a new investigations page', async ({ page }) => {
  const investigationsPage = new InvestigationsPage(page);
  const investigationDetailsPage = new InvestigationDetailsPage(page);
  const investigationsForm = new InvestigationsFormPage(page, 'Create investigation');
  await page.goto('/dashboard/workspaces/investigations');
  await investigationsPage.addNewInvestigation().click();
  await investigationsForm.nameField.fill('Test e2e');
  await investigationsPage.getCreateInvestigationButton().click();
  await investigationsPage.getItemFromList('Test e2e').click();
  await expect(investigationDetailsPage.getInvestigationDetailsPage()).toBeVisible();
  await investigationDetailsPage.addNewInvestigationTag().click();
  await investigationsForm.fillTagInput('Add Test Tag e2e');
  await investigationsForm.getTagInput().press('Enter');
  await expect(investigationDetailsPage.getTag('Add Test Tag e2e')).toBeVisible();
  await investigationDetailsPage.openPopUpButton().click();
  await investigationDetailsPage.getDeleteButton().click();
  await investigationDetailsPage.getConfirmButton().click();
  await page.goto('/dashboard/workspaces/investigations');
  await expect(page.getByRole('link', { name: 'Test e2e' })).toBeHidden();
});
