import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';

export default class SecurityCoverageFormPage {
  formTitle = 'Create a security coverage';
  formLocator: Locator;

  nameField: TextFieldPageModel;
  descriptionField: TextFieldPageModel;
  coverageNameField: SelectFieldPageModel;
  coverageScoreField: TextFieldPageModel;

  constructor(private page: Page) {
    this.formLocator = this.page.getByRole('heading', { name: this.formTitle }).locator('../..');
    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
    this.descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);
    this.coverageNameField = new SelectFieldPageModel(this.page, 'Coverage name', false, this.formLocator);
    this.coverageScoreField = new TextFieldPageModel(this.page, 'Coverage score (0-100)', 'text', this.formLocator);
  }

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
