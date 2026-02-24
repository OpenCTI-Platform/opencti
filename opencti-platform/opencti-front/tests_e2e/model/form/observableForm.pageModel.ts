import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class ObservableFormPage {
  private readonly formLocator;
  private readonly bulkLocator;

  valueField;
  bulkValuesField;
  emailMessageBodyField;
  emailMessageSubjectField;

  constructor(private page: Page) {
    const name = 'Create an observable';
    const bulkName = 'Create multiple observables';
    this.formLocator = this.page.getByRole('heading', { name }).locator('../../..');
    this.bulkLocator = this.page.getByRole('heading', { name: bulkName }).locator('..');

    this.valueField = new TextFieldPageModel(this.page, 'value', 'text', this.formLocator);
    this.bulkValuesField = new TextFieldPageModel(this.page, 'Values (one per line)', 'text', this.bulkLocator);
    this.emailMessageBodyField = new TextFieldPageModel(this.page, 'body', 'text', this.formLocator);
    this.emailMessageSubjectField = new TextFieldPageModel(this.page, 'subject', 'text', this.formLocator);
  }

  chooseType(name: string) {
    return this.formLocator.getByRole('button', { name, exact: true }).click();
  }

  openBulk() {
    return this.formLocator.getByRole('button', { name: 'Create multiple observables', exact: true }).click();
  }

  validateBulk() {
    return this.bulkLocator.getByRole('button', { name: 'Validate', exact: true }).click();
  }

  cancelBulk() {
    return this.bulkLocator.getByRole('button', { name: 'Cancel', exact: true }).click();
  }

  closeBulk() {
    return this.bulkLocator.getByRole('button', { name: 'Close', exact: true }).click();
  }

  submitButton() {
    return this.formLocator.getByRole('button', { name: 'Create', exact: true });
  }

  submit() {
    return this.submitButton().click();
  }

  cancel() {
    return this.formLocator.getByRole('button', { name: 'Cancel', exact: true }).click();
  }
}
