import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';

export default class GroupingFormPage {
  private readonly formLocator = this.page.getByRole('heading', { name: 'Create a grouping' }).locator('../..');

  nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
  contextSelect = new SelectFieldPageModel(this.page, 'Context', false, this.formLocator);

  constructor(private page: Page) {}

  submit() {
    return this.page.getByRole('button', { name: 'Create' }).click();
  }
}
