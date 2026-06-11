import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';

export default class AuthorFormPageModel {
  private readonly formLocator: Locator;

  nameField: TextFieldPageModel;
  descriptionField: TextFieldPageModel;
  entityTypeSelect: SelectFieldPageModel;
  labelsAutocomplete: AutocompleteFieldPageModel;
  markingsAutocomplete: AutocompleteFieldPageModel;
  externalReferencesAutocomplete: AutocompleteFieldPageModel;

  constructor(private page: Page) {
    this.formLocator = this.page.getByLabel('Create an entity');
    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
    this.descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);
    this.entityTypeSelect = new SelectFieldPageModel(this.page, 'Entity type', true, this.formLocator);
    this.labelsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Labels', true, this.formLocator);
    this.markingsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Markings', true, this.formLocator);
    this.externalReferencesAutocomplete = new AutocompleteFieldPageModel(this.page, 'External references', true, this.formLocator);
  }

  getCreateButton() {
    return this.formLocator.getByText('Create', { exact: true });
  }

  getCancelButton() {
    return this.formLocator.getByRole('button', { name: 'Cancel' });
  }
}
