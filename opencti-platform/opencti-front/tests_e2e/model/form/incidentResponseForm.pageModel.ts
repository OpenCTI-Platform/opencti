import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';
import DateFieldPageModel from '../field/DateField.pageModel';
import FileFieldPageModel from '../field/FileField.pageModel';
import ConfidenceFieldPageModel from '../field/ConfidenceField.pageModel';

export default class IncidentResponseFormPage {
  private readonly formLocator;

  nameField;
  incidentDateField;
  severityAutocomplete;
  priorityAutocomplete;
  incidentTypeAutocomplete;
  responseTypeAutocomplete;
  confidenceLevelField;
  descriptionField;
  contentField;
  assigneesAutocomplete;
  participantsAutocomplete;
  authorAutocomplete;
  labelsAutocomplete;
  markingsAutocomplete;
  externalReferencesAutocomplete;
  associatedFileField;

  constructor(private page: Page, formTitle: string) {
    this.formLocator = this.page.getByRole('heading', { name: formTitle }).locator('../..');

    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
    this.incidentDateField = new DateFieldPageModel(this.page, 'Incident date', this.formLocator);
    this.severityAutocomplete = new AutocompleteFieldPageModel(this.page, 'Severity', false, this.formLocator);
    this.priorityAutocomplete = new AutocompleteFieldPageModel(this.page, 'Priority', false, this.formLocator);
    this.incidentTypeAutocomplete = new AutocompleteFieldPageModel(this.page, 'Incident type', true, this.formLocator);
    this.responseTypeAutocomplete = new AutocompleteFieldPageModel(this.page, 'Response type', true, this.formLocator);
    this.confidenceLevelField = new ConfidenceFieldPageModel(this.page, 'Confidence level', this.formLocator);
    this.descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);
    this.contentField = new TextFieldPageModel(this.page, 'Content', 'rich-content', this.formLocator);
    this.assigneesAutocomplete = new AutocompleteFieldPageModel(this.page, 'Assignee(s)', true, this.formLocator);
    this.participantsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Participant(s)', true, this.formLocator);
    this.authorAutocomplete = new AutocompleteFieldPageModel(this.page, 'Author', false, this.formLocator);
    this.labelsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Labels', true, this.formLocator);
    this.markingsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Markings', true, this.formLocator);
    this.externalReferencesAutocomplete = new AutocompleteFieldPageModel(this.page, 'External references', true, this.formLocator);
    this.associatedFileField = new FileFieldPageModel(this.page, 'Associated file', this.formLocator);
  }

  getCreateTitle() {
    return this.page.getByRole('heading', { name: 'Create an incident response' });
  }

  getUpdateTitle() {
    return this.page.getByRole('heading', { name: 'Update an incident response' });
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  getCloseButton() {
    return this.page.getByRole('button', { name: 'Close' });
  }

  getCancelButton() {
    return this.page.getByRole('button', { name: 'Cancel' });
  }
}
