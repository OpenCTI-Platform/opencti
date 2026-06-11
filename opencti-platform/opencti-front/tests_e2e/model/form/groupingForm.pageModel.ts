import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';

export default class GroupingFormPage {
  private readonly formLocator: Locator;

  nameField: TextFieldPageModel;
  contextSelect: SelectFieldPageModel;

  constructor(private page: Page) {
    this.formLocator = this.page.getByRole('heading', { name: 'Create a grouping' }).locator('../..');
    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
    this.contextSelect = new SelectFieldPageModel(this.page, 'Context', false, this.formLocator);
  }

  submit() {
    return this.page.getByRole('button', { name: 'Create' }).click();
  }
}
