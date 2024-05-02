import { Page } from '@playwright/test';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';
import ConfidenceFieldPageModel from '../field/ConfidenceField.pageModel';
import DateFieldPageModel from '../field/DateField.pageModel';
import TextFieldPageModel from '../field/TextField.pageModel';
import FileFieldPageModel from '../field/FileField.pageModel';

export default class ReportFormPage {
  nameField = new TextFieldPageModel(this.page, 'Name', 'text');
  contentField = new TextFieldPageModel(this.page, 'Content', 'rich-content');
  descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area');

  confidenceLevelField = new ConfidenceFieldPageModel(this.page, 'Confidence level');

  publicationDateField = new DateFieldPageModel(this.page, 'Publication date');

  labelsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Labels', true);
  markingsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Markings', true);
  statusAutocomplete = new AutocompleteFieldPageModel(this.page, 'Status', false);
  authorAutocomplete = new AutocompleteFieldPageModel(this.page, 'Author', false);
  assigneesAutocomplete = new AutocompleteFieldPageModel(this.page, 'Assignee(s)', true);
  reportTypesAutocomplete = new AutocompleteFieldPageModel(this.page, 'Report types', true);
  participantsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Participant(s)', true);
  reliabilityAutocomplete = new AutocompleteFieldPageModel(this.page, 'Reliability', false);
  externalReferencesAutocomplete = new AutocompleteFieldPageModel(this.page, 'External references', true);
  associatedFileField = new FileFieldPageModel(this.page, 'Associated file');

  constructor(private page: Page) {}

  getTitle() {
    return this.page.getByRole('heading', { name: 'Create a report' });
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
