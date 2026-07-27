import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';

export default class PirFormPageModel {
  formTitle = 'Create priority intelligence requirement';
  formLocator: Locator;

  nameField: TextFieldPageModel;
  descriptionField: TextFieldPageModel;
  rescanPeriodField: SelectFieldPageModel;
  locationsField: AutocompleteFieldPageModel;
  industriesField: AutocompleteFieldPageModel;

  constructor(private page: Page) {
    this.formLocator = this.page.getByRole('heading', { name: this.formTitle }).locator('../..');
    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
    this.descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);
    this.rescanPeriodField = new SelectFieldPageModel(this.page, 'Rescan period (days)', false, this.formLocator);
    this.locationsField = new AutocompleteFieldPageModel(this.page, 'Targeted locations', true, this.formLocator);
    this.industriesField = new AutocompleteFieldPageModel(this.page, 'Targeted industries', true, this.formLocator);
  }

  getCreateTitle() {
    return this.page.getByRole('heading', { name: this.formTitle });
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  getNextButton() {
    return this.page.getByRole('button', { name: 'Next', exact: true });
  }

  getCancelButton() {
    return this.page.getByRole('button', { name: 'Cancel' });
  }
}
