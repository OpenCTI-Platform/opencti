import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class SecurityCoverageResultFormPage {
  updateTitle = 'Update a security coverage result';
  formLocator: Locator;

  nameField: TextFieldPageModel;

  constructor(private page: Page) {
    this.formLocator = this.page.getByRole('heading', { name: this.updateTitle }).locator('../..');
    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text-no-label', this.formLocator);
  }

  async openUpdateForm() {
    await this.page.locator('#security-coverage-result-split-button').getByRole('button', { name: 'Open menu' }).click();
    return this.page.getByRole('menuitem', { name: 'Update existing Security Coverage Result' }).click();
  }

  getUpdateTitle() {
    return this.page.getByRole('heading', { name: this.updateTitle });
  }

  getResultFromList(name: string) {
    return this.formLocator.getByText(name, { exact: true });
  }

  selectResultToUpdate(name: string) {
    return this.getResultFromList(name).click();
  }

  getEntityFromList(name: string) {
    return this.formLocator.getByText(name, { exact: true });
  }

  selectEntityFromList(name: string) {
    return this.getEntityFromList(name).click();
  }

  getNextButton() {
    return this.formLocator.getByRole('button', { name: 'Next', exact: true });
  }

  goToNextStep() {
    return this.getNextButton().click();
  }

  getCreateButton() {
    return this.formLocator.getByRole('button', { name: 'Create', exact: true });
  }
}
