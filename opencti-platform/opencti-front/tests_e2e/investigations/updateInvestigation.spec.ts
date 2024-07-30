import { expect, test } from '../fixtures/baseFixtures';
import InvestigationsPage from 'tests_e2e/model/investigations.pageModel';
import InvestigationDetailsPage from '../model/investigationDetails.pageModel';
import InvestigationsFormPage from '../model/form/investigationsForm.pageModel';

test('Create a new dashboard page and test update', async ({ page }) => {
  const investigationsPage = new InvestigationsPage(page);
  const investigationDetailsPage = new InvestigationDetailsPage(page);
  const investigationsForm = new InvestigationsFormPage(page);
  await page.goto('/dashboard/workspaces/investigations');
  // await dashboardPage.openButtonModal().hover();
  await investigationsPage.addNewInvestigation().click();
  await investigationsForm.fillNameInput('Test Update e2e');
  await investigationsPage.getCreateInvestigationButton().click();
  await investigationsPage.getItemFromList('Test Update e2e').click();
  await investigationDetailsPage.openPopUpButton().click();
  await investigationDetailsPage.getEditButton().click();
  await investigationsForm.fillNameInput('Modification Test Update e2e');
  await investigationsForm.getCloseButton().click();
  await expect(investigationDetailsPage.getTitle('Modification Test Update e2e')).toBeVisible();
});
