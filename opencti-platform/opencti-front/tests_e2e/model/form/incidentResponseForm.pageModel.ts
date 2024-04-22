import { Page } from "@playwright/test";
import TextFieldPageModel from "../field/TextField.pageModel";
import AutocompleteFieldPageModel from "../field/AutocompleteField.pageModel";
import DateFieldPageModel from "../field/DateField.pageModel";
import FileFieldPageModel from "../field/FileField.pageModel";
import ConfidenceFieldPageModel from "../field/ConfidenceField.pageModel";

export default class IncidentResponseFormPage {
  nameField = new TextFieldPageModel(this.page, 'Name', 'text');
  incidentDateField = new DateFieldPageModel(this.page, 'Incident date');
  severityAutocomplete = new AutocompleteFieldPageModel(this.page, 'Severity', false);
  priorityAutocomplete = new AutocompleteFieldPageModel(this.page, 'Priority', false);
  incidentTypeAutocomplete = new AutocompleteFieldPageModel(this.page, 'Incident type', true);
  responseTypeAutocomplete = new AutocompleteFieldPageModel(this.page, 'Response type', true);
  confidenceLevelField = new ConfidenceFieldPageModel(this.page, 'Confidence level');
  descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area');
  contentField = new TextFieldPageModel(this.page, 'Content', 'rich-content');
  assigneesAutocomplete = new AutocompleteFieldPageModel(this.page, 'Assignee(s)', true);
  participantsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Participant(s)', true);
  authorAutocomplete = new AutocompleteFieldPageModel(this.page, 'Author', false);
  labelsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Labels', true);
  markingsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Markings', true);
  externalReferencesAutocomplete = new AutocompleteFieldPageModel(this.page, 'External references', true);
  associatedFileField = new FileFieldPageModel(this.page, 'Associated file');

  constructor(private page: Page) {}

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