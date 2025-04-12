import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import CaseRfiPage from '../model/caseRfi.pageModel';
import CaseRfiFormPage from '../model/form/caseRfiForm.pageModel';
import CaseRfiDetailsPage from '../model/caseRfiDetails.pageModel';
import ParticipantsFormPage from '../model/form/participantsForm.pageModel';

test('Request for information CRUD', async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);
  const caseRfiPage = new CaseRfiPage(page);
  const caseRfiDetailsPage = new CaseRfiDetailsPage(page);
  const caseRfiCreateForm = new CaseRfiFormPage(page, 'Create a request for information');
  const caseRfiUpdateForm = new CaseRfiFormPage(page, 'Update a request for information');
  const participantsForm = new ParticipantsFormPage(page);

  await page.goto('/dashboard/cases/rfis');
  // Open nav bar once and for all.
  await leftBarPage.open();

  const rfiName = `Case RFI - ${uuid()}`;

  // region Check open/close form.
  // -----------------------------

  await caseRfiPage.getCaseRfiFormCreate().click();
  await expect(caseRfiCreateForm.getCreateTitle()).toBeVisible();
  await caseRfiCreateForm.getCancelButton().click();
  await expect(caseRfiCreateForm.getCreateTitle()).toBeHidden();
  await caseRfiPage.getCaseRfiFormCreate().click();
  await expect(caseRfiCreateForm.getCreateTitle()).toBeVisible();

  // ---------
  // endregion

  // region Fields validation in the form and create.
  // ------------------------------------------------

  await caseRfiCreateForm.nameField.fill('');
  await caseRfiCreateForm.getCreateButton().click();
  await expect(page.getByText('This field is required')).toBeVisible();
  await caseRfiCreateForm.nameField.fill('a');
  await expect(page.getByText('Name must be at least 2 characters')).toBeVisible();
  await caseRfiCreateForm.nameField.fill(rfiName);
  await expect(page.getByText('Name must be at least 2 characters')).toBeHidden();
  await caseRfiCreateForm.getCreateButton().click();

  // ---------
  // endregion

  // region Check data of listed dashboards.
  // ---------------------------------------

  await expect(caseRfiPage.getItemFromList(rfiName)).toBeVisible();

  // ---------
  // endregion

  // region Check details of a dashboard.
  // ------------------------------------

  await caseRfiPage.getItemFromList(rfiName).click();
  await expect(caseRfiDetailsPage.getTitle(rfiName)).toBeVisible();

  // ---------
  // endregion

  // region Manipulate participants.
  // -------------------------------

  await expect(caseRfiDetailsPage.getParticipant('Louise')).toBeHidden();
  await caseRfiDetailsPage.getAddParticipantsButton().click();
  await participantsForm.participantsAutocomplete.selectOption('Louise');
  await participantsForm.getAddButton().click();
  await expect(caseRfiDetailsPage.getParticipant('Louise')).toBeVisible();

  await expect(caseRfiDetailsPage.getParticipant('Anne')).toBeHidden();
  await caseRfiDetailsPage.getUpdateButton().click();
  await caseRfiUpdateForm.participantsAutocomplete.selectOption('Anne');
  await caseRfiUpdateForm.getCloseButton().click();
  await expect(caseRfiDetailsPage.getParticipant('Anne')).toBeVisible();

  // ---------
  // endregion
});
