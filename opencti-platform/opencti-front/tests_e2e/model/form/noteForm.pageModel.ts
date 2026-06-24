import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class NoteFormPage {
  private readonly formLocator: Locator;

  abstractField: TextFieldPageModel;
  contentField: TextFieldPageModel;

  constructor(private page: Page) {
    this.formLocator = this.page.getByRole('heading', { name: 'Create a note' }).locator('../..');
    this.abstractField = new TextFieldPageModel(this.page, 'Abstract', 'text-no-label', this.formLocator);
    this.contentField = new TextFieldPageModel(this.page, 'Content', 'text-area', this.formLocator);
  }

  submit() {
    return this.page.getByRole('button', { name: 'Create' }).click();
  }
}
