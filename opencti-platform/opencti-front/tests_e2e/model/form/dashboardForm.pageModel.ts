import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class DashboardFormPage {
  private readonly formLocator;

  nameField;
  descriptionField;

  constructor(private page: Page, formTitle: string) {
    this.formLocator = this.page.getByRole('heading', { name: formTitle }).locator('../..');

    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
    this.descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);
  }

  getCreateTitle() {
    return this.page.getByRole('heading', { name: 'Create dashboard' });
  }

  getUpdateTitle() {
    return this.page.getByRole('heading', { name: 'Update dashboard' });
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
