import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class LabelFormPageModel {
  private readonly formLocator: Locator;

  valueField: TextFieldPageModel;
  colorField: TextFieldPageModel;

  constructor(private page: Page) {
    this.formLocator = this.page.getByLabel('Create a label');
    this.valueField = new TextFieldPageModel(this.page, 'Value', 'text', this.formLocator);
    this.colorField = new TextFieldPageModel(this.page, 'Color', 'text', this.formLocator);
  }

  getCreateButton() {
    return this.formLocator.getByText('Create', { exact: true });
  }

  getCancelButton() {
    return this.formLocator.getByRole('button', { name: 'Cancel' });
  }
}
