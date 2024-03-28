import { test, expect } from '../fixtures/baseFixtures';
import InvestigationPage from '../model/investigation.pageModel';
import InvestigationFormPage from '../model/investigationForm.pageModel';

test('createInvestigation', async ({ page }) => {
  // BEFORE
  const investigationPage = new InvestigationPage(page);
  const investigationForm = new InvestigationFormPage(page);

  await investigationPage.open();

  // GIVEN
  await investigationPage.openNewInvestigationForm();

  await investigationForm.fillNameInput('add investigation test');
  await investigationForm.fillDescriptionInput('add investigation test description');

  // WHEN
  await investigationForm.getSubmitButton().click();

  // THEN
  await expect(page.getByRole('rowgroup')).toBeVisible();
  await expect(page.getByText('add investigation test')).toBeVisible();
});
