import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class ObservableFormPage {
  private readonly formLocator;

  emailMessageBodyField;
  emailMessageSubjectField;

  constructor(private page: Page) {
    const name = 'Create an observable';
    this.formLocator = this.page.getByRole('heading', { name }).locator('../../..');

    this.emailMessageBodyField = new TextFieldPageModel(this.page, 'body', 'text', this.formLocator);
    this.emailMessageSubjectField = new TextFieldPageModel(this.page, 'subject', 'text', this.formLocator);
  }

  chooseType(name: string) {
    return this.formLocator.getByRole('button', { name, exact: true }).click();
  }

  submit() {
    return this.formLocator.getByRole('button', { name: 'Create', exact: true }).click();
  }
}
