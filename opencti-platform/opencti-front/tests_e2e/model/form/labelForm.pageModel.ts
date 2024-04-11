import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class LabelFormPageModel {
  private readonly formLocator = this.page.getByLabel('Create a label');

  valueField = new TextFieldPageModel(this.page, 'Value', 'text', this.formLocator);
  colorField = new TextFieldPageModel(this.page, 'Color', 'text', this.formLocator);

  constructor(private page: Page) {}

  getCreateButton() {
    return this.formLocator.getByText('Create', { exact: true });
  }

  getCancelButton() {
    return this.formLocator.getByRole('button', { name: 'Cancel' });
  }
}
