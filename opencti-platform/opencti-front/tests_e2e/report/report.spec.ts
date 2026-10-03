import { fileURLToPath } from 'node:url';
import { format } from 'date-fns';
import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import ReportPage from '../model/report.pageModel';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import ReportFormPage from '../model/form/reportForm.pageModel';
import fakeDate from '../utils';
import AuthorFormPageModel from '../model/form/authorForm.pageModel';
import LabelFormPageModel from '../model/form/labelForm.pageModel';
import ExternalReferenceFormPageModel from '../model/form/externalReferenceForm.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import EntitiesTabPageModel from '../model/EntitiesTab.pageModel';

const TEST_MD_PATH = fileURLToPath(new URL('assets/report.test.md', import.meta.url));
const TEST_PDF_PATH = fileURLToPath(new URL('assets/report.test.pdf', import.meta.url));

/**
 * Content of the test
 * -------------------
 * Check open/close form.
 * Check default values of the form.
 * Create a new report.
 * Check fields validation in the form.
 * View report details after creation.
 * Check data of the created report.
 * Update a report.
 * Check updated report.
 * Delete report.
 * Check deletion.
 */
test('Report CRUD', { tag: ['@report', '@knowledge', '@mutation', '@ce', '@group1'] }, async ({ page }) => {
  await fakeDate(page, 'April 1 2024 12:00:00');
  const leftNavigation = new LeftBarPage(page);
  const reportPage = new ReportPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  const reportForm = new ReportFormPage(page);

  await reportPage.goto();
  await reportPage.navigateFromMenu();
  // open nav bar once and for all
  await leftNavigation.open();

  // region Check is displayed
  // -------------------------

  await reportPage.openNewReportForm();
  await expect(reportForm.getCreateTitle()).toBeVisible();
  await reportForm.getCancelButton().click();
  await expect(reportForm.getCreateTitle()).not.toBeVisible();
  await reportPage.openNewReportForm();
  await expect(reportForm.getCreateTitle()).toBeVisible();

  // ---------
  // endregion

  // region Check default values in the form
  // ---------------------------------------

  await expect(reportForm.publicationDateField.getInput()).toHaveValue('2024-04-01 12:00:00 PM');
  await expect(reportForm.confidenceLevelField.getInput()).toHaveValue('100');

  // ---------
  // endregion

  // region Check fields validation
  // ------------------------------

  const reportName = `Report - ${uuid()}`;
  await reportForm.nameField.fill('');
  await reportForm.getCreateButton().click();
  await expect(page.getByText('This field is required')).toBeVisible();
  await reportForm.nameField.fill('t');
  await expect(page.getByText('Name must be at least 2 characters')).toBeVisible();
  await reportForm.nameField.fill(reportName);
  await expect(page.getByText('Name must be at least 2 characters')).toBeHidden();

  await reportForm.publicationDateField.clear();
  await expect(page.getByText('This field is required')).toBeVisible();
  await reportForm.publicationDateField.fill('2023-12-05');
  await expect(page.getByText('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')).toBeVisible();
  await reportForm.publicationDateField.fill('2023-12-05 12:00:00 AM');
  await expect(page.getByText('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')).toBeHidden();

  await reportForm.reportTypesAutocomplete.selectOption('malware');
  await expect(reportForm.reportTypesAutocomplete.getOption('malware')).toBeVisible();
  await reportForm.reportTypesAutocomplete.selectOption('threat-report');
  await expect(reportForm.reportTypesAutocomplete.getOption('threat-report')).toBeVisible();

  await reportForm.reliabilityAutocomplete.selectOption('C - Fairly reliable');
  await expect(reportForm.reliabilityAutocomplete.getOption('C - Fairly reliable')).toBeVisible();

  await reportForm.confidenceLevelField.fillInput('75');
  await expect(reportForm.confidenceLevelField.getSelect().getByText('2 - Probably True')).toBeVisible();

  await reportForm.descriptionField.fill('Test e2e Description');
  await expect(reportForm.descriptionField.get()).toHaveValue('Test e2e Description');

  await reportForm.contentField.fill('This is a Test e2e content');
  await expect(page.getByText('This is a Test e2e content')).toBeVisible();

  await reportForm.assigneesAutocomplete.selectOption('admin');
  await expect(reportForm.assigneesAutocomplete.getOption('admin')).toBeVisible();

  await reportForm.participantsAutocomplete.selectOption('admin');
  await expect(reportForm.participantsAutocomplete.getOption('admin')).toBeVisible();

  await reportForm.authorAutocomplete.selectOption('Allied Universal');
  await expect(reportForm.authorAutocomplete.getOption('Allied Universal')).toBeVisible();

  await reportForm.labelsAutocomplete.selectOption('campaign');
  await expect(reportForm.labelsAutocomplete.getOption('campaign')).toBeVisible();
  await reportForm.labelsAutocomplete.selectOption('report');
  await expect(reportForm.labelsAutocomplete.getOption('report')).toBeVisible();

  await reportForm.markingsAutocomplete.selectOption('PAP:CLEAR');
  await expect(reportForm.markingsAutocomplete.getOption('PAP:CLEAR')).toBeVisible();
  await reportForm.markingsAutocomplete.selectOption('TLP:GREEN');
  await expect(reportForm.markingsAutocomplete.getOption('TLP:GREEN')).toBeVisible();

  await reportForm.associatedFileField.uploadContentFile(TEST_MD_PATH);
  await expect(reportForm.associatedFileField.getByText('report.test.md')).toBeVisible();

  await reportForm.getCreateButton().click();
  await reportPage.getItemFromList(reportName).click();
  await expect(reportDetailsPage.getPage()).toBeVisible();

  // ---------
  // endregion

  // region Control data on report details page
  // ------------------------------------------

  const aiInsightsButton = reportDetailsPage.getAiInsightsButton();
  await expect(aiInsightsButton).toBeVisible();

  let description = reportDetailsPage.getTextForHeading('Description', 'Test e2e Description');
  await expect(description).toBeVisible();

  let publicationDate = reportDetailsPage.getTextForHeading('Publication date', 'December 5, 2023');
  await expect(publicationDate).toBeVisible();

  let reportTypeThreat = reportDetailsPage.getTextForHeading('Report types', 'THREAT-REPORT');
  await expect(reportTypeThreat).toBeVisible();
  let reportTypeMalware = reportDetailsPage.getTextForHeading('Report types', 'MALWARE');
  await expect(reportTypeMalware).toBeVisible();

  let markingClear = reportDetailsPage.getTextForHeading('Marking', 'PAP:CLEAR');
  await expect(markingClear).toBeVisible();
  let markingGreen = reportDetailsPage.getTextForHeading('Marking', 'TLP:GREEN');
  await expect(markingGreen).toBeVisible();

  let author = reportDetailsPage.getTextForHeading('Author', 'ALLIED UNIVERSAL');
  await expect(author).toBeVisible();

  let reliability = reportDetailsPage.getTextForHeading('Reliability', 'C - Fairly reliable');
  await expect(reliability).toBeVisible();

  let confidenceLevel = reportDetailsPage.getTextForHeading('Confidence level', '2 - Probably True');
  await expect(confidenceLevel).toBeVisible();

  let originalCreationDate = reportDetailsPage.getTextForHeading('Original creation date', 'December 5, 2023');
  await expect(originalCreationDate).toBeVisible();

  let processingStatus = reportDetailsPage.getTextForHeading('Processing status', 'NEW');
  await expect(processingStatus).toBeVisible();

  await expect(reportDetailsPage.overview.getAssignee('ADMIN')).toBeVisible();
  await expect(reportDetailsPage.overview.getParticipant('ADMIN')).toBeVisible();

  const revoked = reportDetailsPage.getTextForHeading('Revoked', 'NO');
  await expect(revoked).toBeVisible();

  await expect(reportDetailsPage.overview.getLabel('campaign')).toBeVisible();
  await expect(reportDetailsPage.overview.getLabel('report')).toBeVisible();

  const creators = reportDetailsPage.getTextForHeading('Creators', 'ADMIN');
  await expect(creators).toBeVisible();

  const now = format(new Date(), 'MMMM d, yyyy');
  const creationDate = reportDetailsPage.getTextForHeading('Platform creation date', now);
  await expect(creationDate).toBeVisible();
  const updateDate = reportDetailsPage.getTextForHeading('Modification date', now);
  await expect(updateDate).toBeVisible();

  const historyDescription = reportDetailsPage.getTextForCard('Most recent history', `creates a Report ${reportName}`);
  await expect(historyDescription).toBeVisible();
  const historyDate = reportDetailsPage.getTextForCard('Most recent history', format(new Date(), 'MMM d, yyyy'));
  await expect(historyDate).toBeVisible();

  await reportDetailsPage.tabs.goToDataTab();
  const file = reportDetailsPage.getTextForCard('UPLOADED FILES', 'report.test.md');
  await expect(file).toBeVisible();

  // ---------
  // endregion

  // region Update the report
  // ------------------------

  await reportDetailsPage.tabs.goToOverviewTab();
  await expect(page.getByTestId('report-overview')).toBeVisible();

  const reportNameUpdate = `Report updated - ${uuid()}`;
  await reportDetailsPage.getEditButton().click();
  await reportForm.nameField.fill(reportNameUpdate);
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();

  // region The date picker itself: calendar, persistence, clear
  // -----------------------------------------------------------
  // Exercises DateTimePickerField through its ADORNMENT — the calendar and the
  // clear control — not just by typing. Both broke the last time this field was
  // restyled, and the variant sweep reaches it with no diff naming the file, so
  // a restyle that breaks either turns this red instead of reaching Sandy.
  // Placed before the update below, which then doubles as the restore.
  await reportDetailsPage.getEditButton().click();
  await reportForm.publicationDateField.pickDay('14');
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();
  publicationDate = reportDetailsPage.getTextForHeading('Publication date', 'December 14, 2023');
  await expect(publicationDate).toBeVisible();

  await reportDetailsPage.getEditButton().click();
  await reportForm.publicationDateField.getClearButton().click();
  // The mask coming back is the proof the field is empty AND still a working
  // date field; matched as a pattern because the mask follows the locale.
  await expect(reportForm.publicationDateField.getInput()).toHaveValue(/Y{4}.*M{2}.*D{2}/);
  // Re-picking on a cleared field: the calendar opens on the frozen clock's
  // month (April 2024), so this is deterministic and leaves a valid value.
  await reportForm.publicationDateField.pickDay('25');
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();
  publicationDate = reportDetailsPage.getTextForHeading('Publication date', 'April 25, 2024');
  await expect(publicationDate).toBeVisible();

  // ---------
  // endregion

  await reportDetailsPage.getEditButton().click();
  await reportForm.publicationDateField.fill('2023-12-25 18:00 PM');
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();
  publicationDate = reportDetailsPage.getTextForHeading('Publication date', 'December 25, 2023');
  await expect(publicationDate).toBeVisible();
  originalCreationDate = reportDetailsPage.getTextForHeading('Original creation date', 'December 5, 2023');
  await expect(originalCreationDate).toBeVisible();

  await reportDetailsPage.getEditButton().click();
  await reportForm.reportTypesAutocomplete.selectOption('threat-report');
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();
  reportTypeThreat = reportDetailsPage.getTextForHeading('Report types', 'THREAT-REPORT');
  await expect(reportTypeThreat).toBeHidden();
  reportTypeMalware = reportDetailsPage.getTextForHeading('Report types', 'MALWARE');
  await expect(reportTypeMalware).toBeVisible();

  await reportDetailsPage.getEditButton().click();
  await reportForm.reliabilityAutocomplete.selectOption('B - Usually reliable');
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();
  reliability = reportDetailsPage.getTextForHeading('Reliability', 'B - Usually reliable');
  await expect(reliability).toBeVisible();

  await reportDetailsPage.getEditButton().click();
  await reportForm.confidenceLevelField.fillInput('50');
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();
  confidenceLevel = reportDetailsPage.getTextForHeading('Confidence level', '3 - Possibly True');
  await expect(confidenceLevel).toBeVisible();

  await reportDetailsPage.getEditButton().click();
  await reportForm.descriptionField.fill('Updated test e2e Description');
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();
  description = reportDetailsPage.getTextForHeading('Description', 'Updated test e2e Description');
  await expect(description).toBeVisible();

  await reportDetailsPage.getEditButton().click();
  await reportForm.authorAutocomplete.selectOption('ANSSI');
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();
  author = reportDetailsPage.getTextForHeading('Author', 'ANSSI');
  await expect(author).toBeVisible();

  await reportDetailsPage.getEditButton().click();
  // Each selection commits its own relation mutation, and every response carries a full
  // snapshot of the report. Chaining them lets the response of the first land after the
  // second and overwrite it, so the added marking never reaches the overview panel.
  // Wait for each mutation to land before triggering the next one. Nothing in the DOM can
  // carry that wait: the details view is unmounted while the drawer is open, and the chips
  // of the field only reflect the form state, so the wait is on the responses themselves.
  const waitForMarkingMutation = (mutationName: string) => page.waitForResponse(
    (response) => response.url().includes('/graphql')
      && (response.request().postData() ?? '').includes(mutationName),
  );
  const markingRemoved = waitForMarkingMutation('ReportEditionOverviewRelationDeleteMutation');
  await reportForm.markingsAutocomplete.selectOption('PAP:CLEAR');
  await markingRemoved;
  const markingAdded = waitForMarkingMutation('ReportEditionOverviewRelationAddMutation');
  await reportForm.markingsAutocomplete.selectOption('PAP:GREEN');
  await markingAdded;
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();
  markingClear = reportDetailsPage.getTextForHeading('Marking', 'PAP:CLEAR');
  await expect(markingClear).toBeHidden();
  const markingPapGreen = reportDetailsPage.getTextForHeading('Marking', 'PAP:GREEN');
  await expect(markingPapGreen).toBeVisible();
  markingGreen = reportDetailsPage.getTextForHeading('Marking', 'TLP:GREEN');
  await expect(markingGreen).toBeVisible();

  await reportDetailsPage.getEditButton().click();
  await reportForm.statusAutocomplete.selectOption('IN_PROGRESS');
  await reportForm.getUpdateTitle().click();
  await reportForm.getCloseButton().click();
  processingStatus = reportDetailsPage.getTextForHeading('Processing status', 'IN_PROGRESS');
  await expect(processingStatus).toBeVisible();

  await reportDetailsPage.openLabelsSelect();
  await reportDetailsPage.labelsSelect.selectOption('COVID-19');
  await reportDetailsPage.addLabels();
  await expect(reportDetailsPage.overview.getLabel('campaign')).toBeVisible();
  await expect(reportDetailsPage.overview.getLabel('report')).toBeVisible();
  await expect(reportDetailsPage.overview.getLabel('COVID-19')).toBeVisible();

  // ---------
  // endregion

  // region Delete the report
  // ------------------------

  await reportDetailsPage.delete();
  await leftNavigation.clickOnMenu('Analyses', 'Reports');
  await expect(reportPage.getItemFromList('Updated test e2e')).toBeHidden();

  // ---------
  // endregion
});

/**
 * Content of the test
 * -------------------
 * Create author from report creation form.
 * Create label from report creation form.
 * Create external reference from report creation form.
 * Create report.
 * Check creation for author label and ext ref.
 * Manipulate entities tab.
 * Manipulate observables tab.
 * Delete report by background task.
 * Check deletion.
 */
test('Report live entities creation and relationships', { tag: ['@report', '@knowledge', '@mutation', '@ce', '@group1'] }, async ({ page }) => {
  const leftNavigation = new LeftBarPage(page);
  // const toolbar = new ToolbarPageModel(page);
  const reportPage = new ReportPage(page);
  const reportForm = new ReportFormPage(page);
  const authorForm = new AuthorFormPageModel(page);
  const labelForm = new LabelFormPageModel(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  const externalReferenceForm = new ExternalReferenceFormPageModel(page);
  const entitiesTab = new EntitiesTabPageModel(page);

  await reportPage.goto();
  // open nav bar once and for all
  await leftNavigation.open();

  await reportPage.openNewReportForm();
  const reportName = `Report with created entities - ${uuid()}`;
  const labelName = `threat-${uuid()}`;
  await reportForm.nameField.fill(reportName);

  // region Check author labels and external references creation forms
  // ------------------------------

  // Create author from the report creation form
  // The AUTHOR dialog IS prefilled: CreatedByField passes `inputValue={keyword}`
  // to IdentityCreation, so the create row carries the typed text over. Measured
  // scoped to the dialog — name = "Jeanne Mitchel Report" — so the name can no longer be
  // empty by this path and only the entity type is still required.
  //
  // Do NOT harmonise this with the external-reference block below: that dialog
  // receives no inputValue and genuinely opens empty. The two differ in the
  // product code, not by accident.
  await reportForm.authorAutocomplete.createOption('Jeanne Mitchel Report');
  await authorForm.getCreateButton().click();
  await expect(authorForm.entityTypeSelect.getByText('This field is required')).toBeVisible();
  await authorForm.entityTypeSelect.selectOption('Individual');
  await expect(authorForm.entityTypeSelect.getOption('Individual')).toBeVisible();
  await authorForm.getCreateButton().click();
  await reportForm.authorAutocomplete.selectOption('Jeanne Mitchel Report');
  await expect(reportForm.authorAutocomplete.getOption('Jeanne Mitchel Report')).toBeVisible();

  // Create label from the report creation form
  // Opened through the library's create row instead of the MUI `+`.
  //
  // The two label mounts differ, and this one is `ObjectLabelField`: here the
  // typed text DOES carry into the creation form, so `value` is never empty and
  // only the colour can report itself missing. The other mount — the shared
  // labels view on an entity's details page — opens the same form EMPTY;
  // measured at the pointer, both inputs '' after clicking `Create ‘…’`. Same
  // form component, same `inputValueContextual` prop, opposite outcome, and the
  // reason is not established. Whichever it is, each flow now asserts what its
  // own mount actually does.
  await reportForm.labelsAutocomplete.createOption(labelName);
  await expect(labelForm.valueField.getByText('This field is required')).toBeHidden();
  await labelForm.getCreateButton().click();
  await expect(labelForm.colorField.getByText('This field is required')).toBeVisible();
  await labelForm.colorField.fill('#9d3fb8');
  await expect(labelForm.colorField.getByText('This field is required')).toBeHidden();
  await labelForm.getCreateButton().click();
  await expect(reportForm.labelsAutocomplete.getOption(labelName)).toBeVisible();

  // Create external references
  // The create row OPENS the form; it does not prefill it. Measured on the real
  // incident-response form: after clicking `Create ‘...’` the dialog appears with
  // input[name="source_name"] empty. An earlier version of this block assumed the
  // opposite and dropped the fill, which made creation fail validation silently.
  await reportForm.externalReferencesAutocomplete.createOption('external ref');
  await externalReferenceForm.urlField.fill('bad url');
  await externalReferenceForm.getCreateButton().click();
  await expect(externalReferenceForm.sourceNameField.getByText('This field is required')).toBeVisible();
  await expect(externalReferenceForm.urlField.getByText('The value must be an URL')).toBeVisible();
  await externalReferenceForm.sourceNameField.fill('external ref');
  await externalReferenceForm.urlField.fill('https://github.com/OpenCTI-Platform/opencti');
  await externalReferenceForm.associatedFileField.uploadContentFile(TEST_PDF_PATH);
  await expect(externalReferenceForm.associatedFileField.getByText('report.test.pdf')).toBeVisible();
  await externalReferenceForm.getCreateButton().click();
  await expect(reportForm.externalReferencesAutocomplete.getOption('external ref')).toBeVisible();

  // Create report
  await reportForm.getCreateButton().click();
  await reportPage.getItemFromList(reportName).click();
  await expect(reportDetailsPage.getPage()).toBeVisible();

  // ---------
  // endregion

  // region Control data on report details page
  // ------------------------------------------

  const author = reportDetailsPage.getTextForHeading('Author', 'Jeanne Mitchel Report');
  await expect(author).toBeVisible();

  await expect(reportDetailsPage.overview.getLabel(labelName)).toBeVisible();

  const externalReference = reportDetailsPage.getTextForCard('EXTERNAL REFERENCES', 'external ref (report.test.pdf)');
  await expect(externalReference).toBeVisible();

  // ---------
  // endregion

  // region Manipulate entities on Entities tab
  // ------------------------------------------

  await reportDetailsPage.tabs.goToEntitiesTab();
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

  // region Delete report
  // --------------------
  await leftNavigation.clickOnMenu('Analyses', 'Reports');
  // TODO Fix this
  // await reportPage.checkItemInList(reportName);
  // await toolbar.launchDelete();
  // await leftNavigation.clickOnMenu('Analyses', 'Reports');

  // ---------
  // endregion
});
