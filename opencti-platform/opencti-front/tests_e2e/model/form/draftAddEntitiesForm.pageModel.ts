import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';

export default class DraftAddEntitiesFormPageModel {
  formTitle = 'Create an entity';
  formLocator = this.page.getByRole('heading', { name: this.formTitle }).locator('..');

  nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
  entityTypeField = new SelectFieldPageModel(this.page, 'Entity type', false, this.formLocator);

  constructor(private page: Page) {}

  getCreateTitle() {
    return this.page.getByRole('heading', { name: this.formTitle });
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  getCancelButton() {
    return this.page.getByRole('button', { name: 'Cancel' });
  }
}
