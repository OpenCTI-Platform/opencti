import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class HuntFormPage {
  formTitle = 'Create a hunt';
  formLocator: Locator;

  nameField: TextFieldPageModel;

  constructor(private page: Page) {
    this.formLocator = this.page.getByTestId('hunt-creation-form');
    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
  }

  getCreateTitle() {
    return this.page.getByRole('heading', { name: this.formTitle });
  }

  getSigmaEditor() {
    return this.formLocator.getByTestId('hunt-sigma-editor').locator('textarea');
  }

  getSigmaValidation() {
    return this.formLocator.getByTestId('hunt-sigma-validation');
  }

  getCreateButton() {
    return this.formLocator.getByTestId('hunt-creation-submit');
  }
}
