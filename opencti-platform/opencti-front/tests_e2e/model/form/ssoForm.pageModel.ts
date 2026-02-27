import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import SelectFieldPageModel from '../field/SelectField.pageModel';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';

export default class SSOFormPageModel {
  formTitle = 'Create SAML Authentication';
  formLocator = this.page.getByRole('heading', { name: this.formTitle }).locator('../..');

  nameField = new TextFieldPageModel(this.page, 'Configuration name', 'text', this.formLocator);
  descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);
  issuerField = new TextFieldPageModel(this.page, 'Issuer', 'text-area', this.formLocator);
  samlURLField = new TextFieldPageModel(this.page, 'SAML URL', 'text-area', this.formLocator);
  idpCertField = new TextFieldPageModel(this.page, 'IDP Certificate', 'text-area', this.formLocator);
  privateKeyField = new SelectFieldPageModel(this.page, 'Private key', false, this.formLocator);
  valuePKField = new TextFieldPageModel(this.page, 'Value', 'text-area', this.formLocator);

  // locationsField = new AutocompleteFieldPageModel(this.page, 'Targeted locations', true, this.formLocator);
  //
  // industriesField = new AutocompleteFieldPageModel(this.page, 'Targeted industries', true, this.formLocator);

  constructor(private page: Page) {}

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
