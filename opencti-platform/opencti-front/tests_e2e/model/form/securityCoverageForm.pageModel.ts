import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';

export default class SecurityCoverageFormPage {
  formTitle = 'Create a security coverage';
  formLocator = this.page.getByRole('heading', { name: this.formTitle }).locator('../..');

  nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
  descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);
  coverageNameField = new SelectFieldPageModel(this.page, 'Coverage name', false, this.formLocator);
  coverageScoreField = new TextFieldPageModel(this.page, 'Coverage score (0-100)', 'text', this.formLocator);

  constructor(private page: Page) {}

  chooseManualCreation() {
    return this.formLocator.getByText('Manual input').click();
  }

  getEntityFromList(name: string) {
    return this.formLocator.getByText(name);
  }

  selectEntityFromList(name: string) {
    return this.getEntityFromList(name).click();
  }

  addMetric() {
    return this.formLocator.getByRole('button', { name: 'Add coverage metric' }).click();
  }

  getCreateTitle() {
    return this.page.getByRole('heading', { name: this.formTitle });
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  getCancelButton() {
    return this.page.getByRole('button', { name: 'Cancel' });
  }
}
