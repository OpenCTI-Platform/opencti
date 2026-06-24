import { Page } from '@playwright/test';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';
import ConfidenceFieldPageModel from '../field/ConfidenceField.pageModel';
import DateFieldPageModel from '../field/DateField.pageModel';
import TextFieldPageModel from '../field/TextField.pageModel';
import FileFieldPageModel from '../field/FileField.pageModel';

export default class ReportFormPage {
  nameField: TextFieldPageModel;
  contentField: TextFieldPageModel;
  descriptionField: TextFieldPageModel;
  confidenceLevelField: ConfidenceFieldPageModel;
  publicationDateField: DateFieldPageModel;
  labelsAutocomplete: AutocompleteFieldPageModel;
  markingsAutocomplete: AutocompleteFieldPageModel;
  statusAutocomplete: AutocompleteFieldPageModel;
  authorAutocomplete: AutocompleteFieldPageModel;
  assigneesAutocomplete: AutocompleteFieldPageModel;
  reportTypesAutocomplete: AutocompleteFieldPageModel;
  participantsAutocomplete: AutocompleteFieldPageModel;
  reliabilityAutocomplete: AutocompleteFieldPageModel;
  externalReferencesAutocomplete: AutocompleteFieldPageModel;
  associatedFileField: FileFieldPageModel;

  constructor(private page: Page) {
    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text-no-label');
    this.contentField = new TextFieldPageModel(this.page, 'Content', 'rich-content');
    this.descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area');
    this.confidenceLevelField = new ConfidenceFieldPageModel(this.page, 'Confidence level');
    this.publicationDateField = new DateFieldPageModel(this.page, 'Publication date');
    this.labelsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Labels', true);
    this.markingsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Markings', true);
    this.statusAutocomplete = new AutocompleteFieldPageModel(this.page, 'Status', false);
    this.authorAutocomplete = new AutocompleteFieldPageModel(this.page, 'Author', false);
    this.assigneesAutocomplete = new AutocompleteFieldPageModel(this.page, 'Assignee(s)', true);
    this.reportTypesAutocomplete = new AutocompleteFieldPageModel(this.page, 'Report types', true);
    this.participantsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Participant(s)', true);
    this.reliabilityAutocomplete = new AutocompleteFieldPageModel(this.page, 'Reliability', false);
    this.externalReferencesAutocomplete = new AutocompleteFieldPageModel(this.page, 'External references', true);
    this.associatedFileField = new FileFieldPageModel(this.page, 'Associated file');
  }

  getCreateTitle() {
    return this.page.getByRole('heading', { name: 'Create a report' });
  }

  getUpdateTitle() {
    return this.page.getByRole('heading', { name: 'Update a report' });
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
