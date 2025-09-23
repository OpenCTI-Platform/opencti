import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import CaseRftPage from '../model/caseRft.pageModel';
import CaseRftDetailsPage from '../model/caseRftDetails.pageModel';
import CaseRftFormPage from '../model/form/caseRftForm.pageModel';

test('Request for takedown CRUD', async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);
  const caseRftPage = new CaseRftPage(page);
  const caseRftDetailsPage = new CaseRftDetailsPage(page);
  const caseRftCreateForm = new CaseRftFormPage(page, 'Create a request for takedown');

  await page.goto('/dashboard/cases/rfts');
  // Open nav bar one and for all.
  await leftBarPage.open();

  const rftName = `Case RFT - ${uuid()}`;

  // region Check open/close form.
  // -----------------------------

  await caseRftPage.getCaseRftFormCreate().click();
  await expect(caseRftCreateForm.getCreateTitle()).toBeVisible();
  await caseRftCreateForm.getCancelButton().click();
  await expect(caseRftCreateForm.getCreateTitle()).toBeHidden();
  await caseRftPage.getCaseRftFormCreate().click();
  await expect(caseRftCreateForm.getCreateTitle()).toBeVisible();

  // ---------
  // endregion

  // region Fields validation in the form and create.
  // ------------------------------------------------

  await caseRftCreateForm.nameField.fill('');
  await caseRftCreateForm.getCreateButton().click();
  await expect(page.getByText('This field is required')).toBeVisible();
  await caseRftCreateForm.nameField.fill('a');
  await expect(page.getByText('Name must be at least 2 characters')).toBeVisible();
  await caseRftCreateForm.nameField.fill(rftName);
  await expect(page.getByText('Name must be at least 2 characters')).toBeHidden();
  await caseRftCreateForm.getCreateButton().click();

  // ---------
  // endregion

  await expect(caseRftPage.getItemFromList(rftName)).toBeVisible();
  await caseRftPage.getItemFromList(rftName).click();
  await expect(caseRftDetailsPage.getTitle(rftName)).toBeVisible();
});
