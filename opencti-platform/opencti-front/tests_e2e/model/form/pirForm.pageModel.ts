import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';

export default class PirFormPageModel {
  formTitle = 'Create priority intelligence requirement';
  formLocator = this.page.getByRole('heading', { name: this.formTitle }).locator('../..');

  nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
  descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);
  rescanPeriodField = new SelectFieldPageModel(this.page, 'Rescan period (days)', false, this.formLocator);
  locationsField = new AutocompleteFieldPageModel(this.page, 'Targeted locations', true, this.formLocator);
  industriesField = new AutocompleteFieldPageModel(this.page, 'Targeted industries', true, this.formLocator);

  constructor(private page: Page) {}

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
