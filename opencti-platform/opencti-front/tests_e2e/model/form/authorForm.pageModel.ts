import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';

export default class AuthorFormPageModel {
  private readonly formLocator = this.page.getByLabel('Create an entity');

  nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
  descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);
  entityTypeSelect = new SelectFieldPageModel(this.page, 'Entity type', true, this.formLocator);
  labelsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Labels', true, this.formLocator);
  markingsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Markings', true, this.formLocator);
  externalReferencesAutocomplete = new AutocompleteFieldPageModel(this.page, 'External references', true, this.formLocator);

  constructor(private page: Page) {}

  getCreateButton() {
    return this.formLocator.getByText('Create', { exact: true });
  }

  getCancelButton() {
    return this.formLocator.getByRole('button', { name: 'Cancel' });
  }
}
