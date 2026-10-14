import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class SecurityCoverageResultFormPage {
  updateTitle = 'Update a security coverage result';
  formLocator: Locator;

  nameField: TextFieldPageModel;

  constructor(private page: Page) {
    this.formLocator = this.page.getByRole('heading', { name: this.updateTitle }).locator('../..');
    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
  }

  async openUpdateForm() {
    await this.page.getByRole('button', { name: 'Add manual Coverage Result' }).click();
    return this.page.getByRole('menuitem', { name: 'Update existing Security Coverage Result' }).click();
  }

  getUpdateTitle() {
    return this.page.getByRole('heading', { name: this.updateTitle });
  }

  getResultFromList(name: string) {
    return this.formLocator.getByText(name, { exact: true });
  }

  selectResultToUpdate() {
    return this.formLocator.getByRole('button', { name: 'Update', exact: true }).first().click();
  }

  getEntityFromList(name: string) {
    return this.formLocator.getByText(name, { exact: true });
  }

  selectEntityFromList(name: string) {
    return this.getEntityFromList(name).click();
  }

  goToNextStep() {
    return this.formLocator.getByRole('button', { name: 'Next', exact: true }).click();
  }

  getCreateButton() {
    return this.formLocator.getByRole('button', { name: 'Create', exact: true });
  }
}
