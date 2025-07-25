import path from 'path';
import { expect, test } from '../fixtures/baseFixtures';
import ExternalReferenceFormPageModel from '../model/form/externalReferenceForm.pageModel';
import ExternalReferencePage from '../model/externalReference.pageModel';
import ExternalReferenceDetailsPage from '../model/externalReferenceDetails.pageModel';

test('Create a new external reference', async ({ page }) => {
  const externalReferencePage = new ExternalReferencePage(page);
  const externalReferenceForm = new ExternalReferenceFormPageModel(page);
  const externalReferenceDetails = new ExternalReferenceDetailsPage(page);

  // go to external references
  await externalReferencePage.goto();
  await expect(externalReferencePage.getPage()).toBeVisible();
  // add a new external reference
  await externalReferencePage.addNew();
  await externalReferenceForm.sourceNameField.fill('Test external reference source name field e2e');
  await externalReferenceForm.associatedFileField.uploadContentFile(path.join(__dirname, 'assets/report.test.pdf'));
  await externalReferenceForm.getCreateButton().click();
  // open it
  await externalReferencePage.getItemFromList('Test external reference source name field e2e').click();
  await expect(externalReferenceDetails.getPage()).toBeVisible();
  await expect(externalReferenceDetails.getTitle('Test external reference source name field e2e')).toBeVisible();
});
