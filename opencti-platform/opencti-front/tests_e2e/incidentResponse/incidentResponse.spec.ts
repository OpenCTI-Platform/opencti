import * as path from 'path';
import { format } from 'date-fns';
import { v4 as uuid } from 'uuid';
import IncidentResponsePage from 'tests_e2e/model/incidentResponse.pageModel';
import IncidentResponseFormPage from 'tests_e2e/model/form/incidentResponseForm.pageModel';
import IncidentResponseDetailsPage from 'tests_e2e/model/incidentResponseDetails.pageModel';
import { expect, test } from '../fixtures/baseFixtures';
import fakeDate from '../utils';
import AuthorFormPageModel from '../model/form/authorForm.pageModel';
import LabelFormPageModel from '../model/form/labelForm.pageModel';
import ExternalReferenceFormPageModel from '../model/form/externalReferenceForm.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import ToolbarPageModel from '../model/toolbar.pageModel';
import EntitiesTabPageModel from '../model/EntitiesTab.pageModel';

/**
 * Content of the test
 * -------------------
 * Check open/close form.
 * Check default values of the form.
 * Create a new incident response.
 * Check fields validation in the form.
 * View incident response details after creation.
 * Check data of the created incident response.
 * Update an incident response.
 * Check updated incident response.
 * Delete incident response.
 * Check deletion.
 */
test('Incident Response Creation', async ({ page }) => {
  await fakeDate(page, 'April 1 2024 12:00:00');
  const leftNavigation = new LeftBarPage(page);
  const incidentResponsePage = new IncidentResponsePage(page);
  const incidentResponseDetailsPage = new IncidentResponseDetailsPage(page);
  const incidentResponseForm = new IncidentResponseFormPage(page, 'Create an incident response');
  const incidentResponseUpdateForm = new IncidentResponseFormPage(page, 'Update an incident response');

  await page.goto('/dashboard/cases/incidents');
  // open nav bar once and for all
  await leftNavigation.open();

  // region Check is displayed
  // -------------------------

  await incidentResponsePage.openNewIncidentResponseForm();
  await expect(incidentResponseForm.getCreateTitle()).toBeVisible();
  await incidentResponseForm.getCancelButton().click();
  await expect(incidentResponseForm.getCreateTitle()).not.toBeVisible();
  await incidentResponsePage.openNewIncidentResponseForm();
  await expect(incidentResponseForm.getCreateTitle()).toBeVisible();

  // ---------
  // endregion

  // region Check default values in the form
  // ---------------------------------------

  await expect(incidentResponseForm.incidentDateField.getInput()).toHaveValue('2024-04-01 12:00 PM');
  await expect(incidentResponseForm.confidenceLevelField.getInput()).toHaveValue('100');

  // ---------
  // endregion

  // region Check fields validation
  // ------------------------------

  const incidentResponseName = `Incident Response - ${uuid()}`;
  await incidentResponseForm.nameField.fill('');
  await incidentResponseForm.getCreateButton().click();
  await expect(page.getByText('This field is required')).toBeVisible();
  await incidentResponseForm.nameField.fill('t');
  await expect(page.getByText('Name must be at least 2 characters')).toBeVisible();
  await incidentResponseForm.nameField.fill(incidentResponseName);
  await expect(page.getByText('Name must be at least 2 characters')).toBeHidden();

  await incidentResponseForm.severityAutocomplete.selectOption('low');
  await expect(incidentResponseForm.severityAutocomplete.getOption('low')).toBeVisible();
  await incidentResponseForm.severityAutocomplete.selectOption('critical');
  await expect(incidentResponseForm.severityAutocomplete.getOption('critical')).toBeVisible();

  await incidentResponseForm.priorityAutocomplete.selectOption('P2');
  await expect(incidentResponseForm.priorityAutocomplete.getOption('P2')).toBeVisible();

  await incidentResponseForm.incidentTypeAutocomplete.selectOption('ransomware');
  await expect(incidentResponseForm.incidentTypeAutocomplete.getOption('ransomware')).toBeVisible();

  await incidentResponseForm.confidenceLevelField.fillInput('75');
  await expect(incidentResponseForm.confidenceLevelField.getSelect().getByText('2 - Probably True')).toBeVisible();

  await incidentResponseForm.descriptionField.fill('Test e2e Description');
  await expect(incidentResponseForm.descriptionField.get()).toHaveValue('Test e2e Description');

  await incidentResponseForm.contentField.fill('This is a Test e2e content');
  await expect(page.getByText('This is a Test e2e content')).toBeVisible();

  await incidentResponseForm.assigneesAutocomplete.selectOption('admin');
  await expect(incidentResponseForm.assigneesAutocomplete.getOption('admin')).toBeVisible();

  await incidentResponseForm.participantsAutocomplete.selectOption('admin');
  await expect(incidentResponseForm.participantsAutocomplete.getOption('admin')).toBeVisible();

  await incidentResponseForm.authorAutocomplete.selectOption('Allied Universal');
  await expect(incidentResponseForm.authorAutocomplete.getOption('Allied Universal')).toBeVisible();

  await incidentResponseForm.labelsAutocomplete.selectOption('campaign');
  await expect(incidentResponseForm.labelsAutocomplete.getOption('campaign')).toBeVisible();
  await incidentResponseForm.labelsAutocomplete.selectOption('report');
  await expect(incidentResponseForm.labelsAutocomplete.getOption('report')).toBeVisible();

  await incidentResponseForm.markingsAutocomplete.selectOption('PAP:CLEAR');
  await expect(incidentResponseForm.markingsAutocomplete.getOption('PAP:CLEAR')).toBeVisible();
  await incidentResponseForm.markingsAutocomplete.selectOption('TLP:GREEN');
  await expect(incidentResponseForm.markingsAutocomplete.getOption('TLP:GREEN')).toBeVisible();

  await incidentResponseForm.associatedFileField.uploadContentFile(path.join(__dirname, 'assets/incidentResponse.test.md'));
  await expect(incidentResponseForm.associatedFileField.getByText('incidentResponse.test.md')).toBeVisible();

  await incidentResponseForm.getCreateButton().click();
  await incidentResponsePage.getItemFromList(incidentResponseName).click();
  await expect(incidentResponseDetailsPage.getIncidentResponseDetailsPage()).toBeVisible();

  // ---------
  // endregion

  // region Control data on incident response details page
  // ------------------------------------------

  await expect(incidentResponseDetailsPage.getTitle(incidentResponseName)).toBeVisible();

  let description = incidentResponseDetailsPage.getTextForHeading('Description', 'Test e2e Description');
  await expect(description).toBeVisible();

  let priority = incidentResponseDetailsPage.getTextForHeading('Priority', 'P2');
  await expect(priority).toBeVisible();
  let severity = incidentResponseDetailsPage.getTextForHeading('Severity', 'critical');
  await expect(severity).toBeVisible();

  let markingClear = incidentResponseDetailsPage.getTextForHeading('Marking', 'PAP:CLEAR');
  await expect(markingClear).toBeVisible();
  let markingGreen = incidentResponseDetailsPage.getTextForHeading('Marking', 'TLP:GREEN');
  await expect(markingGreen).toBeVisible();

  let author = incidentResponseDetailsPage.getTextForHeading('Author', 'ALLIED UNIVERSAL');
  await expect(author).toBeVisible();

  let confidenceLevel = incidentResponseDetailsPage.getTextForHeading('Confidence level', '2 - Probably True');
  await expect(confidenceLevel).toBeVisible();

  let originalCreationDate = incidentResponseDetailsPage.getTextForHeading('Original creation date', 'April 1, 2024');
  await expect(originalCreationDate).toBeVisible();

  const processingStatus = incidentResponseDetailsPage.getTextForHeading('Processing status', 'DISABLED');
  await expect(processingStatus).toBeVisible();

  await expect(incidentResponseDetailsPage.overview.getAssignee('ADMIN')).toBeVisible();
  await expect(incidentResponseDetailsPage.overview.getParticipant('ADMIN')).toBeVisible();

  const revoked = incidentResponseDetailsPage.getTextForHeading('Revoked', 'NO');
  await expect(revoked).toBeVisible();

  await expect(incidentResponseDetailsPage.overview.getLabel('campaign')).toBeVisible();
  await expect(incidentResponseDetailsPage.overview.getLabel('report')).toBeVisible();

  const creators = incidentResponseDetailsPage.getTextForHeading('Creators', 'ADMIN');
  await expect(creators).toBeVisible();

  const now = format(new Date(), 'MMMM d, yyyy');
  const creationDate = incidentResponseDetailsPage.getTextForHeading('Platform creation date', now);
  await expect(creationDate).toBeVisible();
  const updateDate = incidentResponseDetailsPage.getTextForHeading('Modification date', now);
  await expect(updateDate).toBeVisible();

  const historyDescription = incidentResponseDetailsPage.getTextForHeading('Most recent history', `admin creates a Case-Incident ${incidentResponseName}`);
  await expect(historyDescription).toBeVisible();
  const historyDate = incidentResponseDetailsPage.getTextForHeading('Most recent history', format(new Date(), 'MMM d, yyyy'));
  await expect(historyDate).toBeVisible();

  await incidentResponseDetailsPage.goToDataTab();
  const file = incidentResponseDetailsPage.getTextForHeading('UPLOADED FILES', 'incidentResponse.test.md');
  await expect(file).toBeVisible();

  // ---------
  // endregion

  // region Update the incident response
  // ------------------------

  await incidentResponseDetailsPage.goToOverviewTab();

  const incidentResponseNameUpdate = `Incident Response updated - ${uuid()}`;
  await incidentResponseDetailsPage.getEditButton().click();
  await incidentResponseUpdateForm.nameField.fill(incidentResponseNameUpdate);
  await incidentResponseUpdateForm.getUpdateTitle().click();
  await incidentResponseUpdateForm.getCloseButton().click();

  await incidentResponseDetailsPage.getEditButton().click();
  await incidentResponseUpdateForm.incidentDateField.fill('2023-12-25 18:00 PM');
  await incidentResponseUpdateForm.getUpdateTitle().click();
  await incidentResponseUpdateForm.getCloseButton().click();
  originalCreationDate = incidentResponseDetailsPage.getTextForHeading('Original creation date', 'December 25, 2023');
  await expect(originalCreationDate).toBeVisible();

  await incidentResponseDetailsPage.getEditButton().click();
  await incidentResponseUpdateForm.severityAutocomplete.selectOption('high');
  await incidentResponseUpdateForm.getUpdateTitle().click();
  await incidentResponseUpdateForm.getCloseButton().click();
  severity = incidentResponseDetailsPage.getTextForHeading('Severity', 'critical');
  await expect(severity).toBeHidden();
  severity = incidentResponseDetailsPage.getTextForHeading('Severity', 'high');
  await expect(severity).toBeVisible();

  await incidentResponseDetailsPage.getEditButton().click();
  await incidentResponseUpdateForm.priorityAutocomplete.selectOption('P3');
  await incidentResponseUpdateForm.getUpdateTitle().click();
  await incidentResponseUpdateForm.getCloseButton().click();
  priority = incidentResponseDetailsPage.getTextForHeading('Priority', 'P3');
  await expect(priority).toBeVisible();

  await incidentResponseDetailsPage.getEditButton().click();
  await incidentResponseUpdateForm.confidenceLevelField.fillInput('50');
  await incidentResponseUpdateForm.getUpdateTitle().click();
  await incidentResponseUpdateForm.getCloseButton().click();
  confidenceLevel = incidentResponseDetailsPage.getTextForHeading('Confidence level', '3 - Possibly True');
  await expect(confidenceLevel).toBeVisible();

  await incidentResponseDetailsPage.getEditButton().click();
  await incidentResponseUpdateForm.descriptionField.fill('Updated test e2e Description');
  await incidentResponseUpdateForm.getUpdateTitle().click();
  await incidentResponseUpdateForm.getCloseButton().click();
  description = incidentResponseDetailsPage.getTextForHeading('Description', 'Updated test e2e Description');
  await expect(description).toBeVisible();

  await incidentResponseDetailsPage.getEditButton().click();
  await incidentResponseUpdateForm.authorAutocomplete.selectOption('ANSSI');
  await incidentResponseUpdateForm.getUpdateTitle().click();
  await incidentResponseUpdateForm.getCloseButton().click();
  author = incidentResponseDetailsPage.getTextForHeading('Author', 'ANSSI');
  await expect(author).toBeVisible();

  await incidentResponseDetailsPage.getEditButton().click();
  await incidentResponseUpdateForm.markingsAutocomplete.selectOption('PAP:CLEAR');
  await incidentResponseUpdateForm.markingsAutocomplete.selectOption('PAP:GREEN');
  await incidentResponseUpdateForm.getUpdateTitle().click();
  await incidentResponseUpdateForm.getCloseButton().click();
  markingClear = incidentResponseDetailsPage.getTextForHeading('Marking', 'PAP:CLEAR');
  await expect(markingClear).toBeHidden();
  const markingPapGreen = incidentResponseDetailsPage.getTextForHeading('Marking', 'PAP:GREEN');
  await expect(markingPapGreen).toBeVisible();
  markingGreen = incidentResponseDetailsPage.getTextForHeading('Marking', 'TLP:GREEN');
  await expect(markingGreen).toBeVisible();

  await incidentResponseDetailsPage.getEditButton().click();
  await incidentResponseUpdateForm.responseTypeAutocomplete.selectOption('data-leak');
  await incidentResponseUpdateForm.getUpdateTitle().click();
  await incidentResponseUpdateForm.getCloseButton().click();
  const incidentResponseType = incidentResponseDetailsPage.getTextForHeading('Incident response type', 'data-leak');
  await expect(incidentResponseType).toBeVisible();

  await incidentResponseDetailsPage.openLabelsSelect();
  await incidentResponseDetailsPage.labelsSelect.selectOption('covid-19');
  await incidentResponseDetailsPage.addLabels();
  await expect(incidentResponseDetailsPage.overview.getLabel('campaign')).toBeVisible();
  await expect(incidentResponseDetailsPage.overview.getLabel('report')).toBeVisible();
  await expect(incidentResponseDetailsPage.overview.getLabel('covid-19')).toBeVisible();

  // ---------
  // endregion

  // region Delete the incident response
  // ------------------------

  await incidentResponseDetailsPage.delete();
  await leftNavigation.clickOnMenu('Cases', 'Incident responses');
  await expect(incidentResponsePage.getItemFromList('Updated test e2e')).toBeHidden();

  // ---------
  // endregion
});

/**
 * Content of the test
 * -------------------
 * Create author from incident response creation form.
 * Create label from incident response creation form.
 * Create external reference from incident response creation form.
 * Create incident response.
 * Check creation for author label and ext ref.
 * Manipulate entities tab.
 * Manipulate observables tab.
 * Delete incident response by background task.
 * Check deletion.
 */
test('Incident response live entities creation and relationships', async ({ page }) => {
  const leftNavigation = new LeftBarPage(page);
  const toolbar = new ToolbarPageModel(page);
  const incidentResponsePage = new IncidentResponsePage(page);
  const incidentResponseForm = new IncidentResponseFormPage(page, 'Create an incident response');
  const authorForm = new AuthorFormPageModel(page);
  const labelForm = new LabelFormPageModel(page);
  const incidentResponseDetailsPage = new IncidentResponseDetailsPage(page);
  const externalReferenceForm = new ExternalReferenceFormPageModel(page);
  const entitiesTab = new EntitiesTabPageModel(page);

  await page.goto('/dashboard/cases/incidents');
  // open nav bar once and for all
  await leftNavigation.open();

  await incidentResponsePage.openNewIncidentResponseForm();
  const incidentResponseName = `Incident response with created entities - ${uuid()}`;
  await incidentResponseForm.nameField.fill(incidentResponseName);

  // region Check author labels and external references creation forms
  // ------------------------------

  // Create author from the incident response creation form
  await incidentResponseForm.authorAutocomplete.openAddOptionForm();
  await authorForm.getCreateButton().click();
  await expect(authorForm.nameField.getByText('This field is required')).toBeVisible();
  await expect(authorForm.entityTypeSelect.getByText('This field is required')).toBeVisible();
  await authorForm.nameField.fill('Jeanne Mitchel');
  await expect(authorForm.nameField.getByText('This field is required')).toBeHidden();
  await authorForm.entityTypeSelect.selectOption('Individual');
  await expect(authorForm.entityTypeSelect.getOption('Individual')).toBeVisible();
  await authorForm.getCreateButton().click();
  await incidentResponseForm.authorAutocomplete.selectOption('Jeanne Mitchel');
  await expect(incidentResponseForm.authorAutocomplete.getOption('Jeanne Mitchel')).toBeVisible();

  // Create label from the incident response creation form
  await incidentResponseForm.labelsAutocomplete.openAddOptionForm();
  await labelForm.getCreateButton().click();
  await expect(labelForm.valueField.getByText('This field is required')).toBeVisible();
  await expect(labelForm.colorField.getByText('This field is required')).toBeVisible();
  await labelForm.valueField.fill('threat');
  await expect(labelForm.valueField.getByText('This field is required')).toBeHidden();
  await labelForm.colorField.fill('#9d3fb8');
  await expect(labelForm.colorField.getByText('This field is required')).toBeHidden();
  await labelForm.getCreateButton().click();
  await expect(incidentResponseForm.labelsAutocomplete.getOption('threat')).toBeVisible();

  // Create external references
  await incidentResponseForm.externalReferencesAutocomplete.openAddOptionForm();
  await externalReferenceForm.urlField.fill('bad url');
  await externalReferenceForm.getCreateButton().click();
  await expect(externalReferenceForm.sourceNameField.getByText('This field is required')).toBeVisible();
  await expect(externalReferenceForm.urlField.getByText('The value must be an URL')).toBeVisible();
  await externalReferenceForm.sourceNameField.fill('external ref incident response');
  await externalReferenceForm.urlField.fill('https://github.com/OpenCTI-Platform/client-python');
  await externalReferenceForm.associatedFileField.uploadContentFile(path.join(__dirname, 'assets/incidentResponse.test.pdf'));
  await expect(externalReferenceForm.associatedFileField.getByText('incidentResponse.test.pdf')).toBeVisible();
  await externalReferenceForm.getCreateButton().click();
  await expect(incidentResponseForm.externalReferencesAutocomplete.getOption('external ref')).toBeVisible();

  // Create incident response
  await incidentResponseForm.getCreateButton().click();
  await incidentResponsePage.getItemFromList(incidentResponseName).click();
  await expect(incidentResponseDetailsPage.getIncidentResponseDetailsPage()).toBeVisible();

  // ---------
  // endregion

  // region Control data on incident response details page
  // ------------------------------------------

  const author = incidentResponseDetailsPage.getTextForHeading('Author', 'Jeanne Mitchel');
  await expect(author).toBeVisible();

  await expect(incidentResponseDetailsPage.overview.getLabel('threat')).toBeVisible();

  // ---------
  // endregion

  // region Manipulate entities on Entities tab
  // ------------------------------------------

  await incidentResponseDetailsPage.goToEntitiesTab();
  await entitiesTab.clickAddEntities();
  await entitiesTab.search('note');
  await entitiesTab.addEntity('This is a note');
  await entitiesTab.closeAddEntity();
  await expect(page.getByRole('link', { name: 'Note This is a note note' })).toBeVisible();

  // ---------
  // endregion

  // region Manipulate entities on Observables tab
  // ---------------------------------------------

  // TODO after Table component refacto

  // ---------
  // endregion

  // region Delete incident response
  // --------------------
  await leftNavigation.clickOnMenu('Cases', 'Incident responses');
  await incidentResponsePage.checkItemInList(incidentResponseName);
  await toolbar.launchDelete();
  await leftNavigation.clickOnMenu('Cases', 'Incident responses');

  // ---------
  // endregion
});
