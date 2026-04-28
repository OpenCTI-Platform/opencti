import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class NoteFormPage {
  private readonly formLocator = this.page.getByRole('heading', { name: 'Create a note' }).locator('../..');

  abstractField = new TextFieldPageModel(this.page, 'Abstract', 'text-no-label', this.formLocator);
  contentField = new TextFieldPageModel(this.page, 'Content', 'text-area', this.formLocator);

  constructor(private page: Page) {}

  submit() {
    return this.page.getByRole('button', { name: 'Create' }).click();
  }
}
