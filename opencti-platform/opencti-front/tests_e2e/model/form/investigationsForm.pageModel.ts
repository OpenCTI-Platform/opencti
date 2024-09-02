import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class InvestigationsFormPage {
  private readonly formLocator;

  nameField;

  constructor(private page: Page, formTitle: string) {
    this.formLocator = this.page.getByRole('heading', { name: formTitle }).locator('../..');

    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
  }

  getCloseButton() {
    return this.page.getByRole('button', { name: 'Close' });
  }

  getTagInput() {
    return this.page.getByPlaceholder('New tag');
  }

  async fillTagInput(input: string) {
    await this.getTagInput().click();
    return this.getTagInput().fill(input);
  }
}
