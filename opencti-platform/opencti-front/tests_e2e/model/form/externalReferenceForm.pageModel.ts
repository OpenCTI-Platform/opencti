import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import FileFieldPageModel from '../field/FileField.pageModel';

export default class ExternalReferenceFormPageModel {
  private readonly formLocator = this.page.getByRole('heading', { name: 'Create External reference' }).locator('../..');

  sourceNameField = new TextFieldPageModel(this.page, 'Source name', 'text-no-label', this.formLocator);
  externalIdField = new TextFieldPageModel(this.page, 'External ID', 'text', this.formLocator);
  urlField = new TextFieldPageModel(this.page, 'URL', 'text', this.formLocator);
  associatedFileField = new FileFieldPageModel(this.page, 'Associated file', this.formLocator);
  descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);

  constructor(private page: Page) {}

  getCreateButton() {
    return this.formLocator.getByText('Create', { exact: true });
  }

  getCancelButton() {
    return this.formLocator.getByRole('button', { name: 'Cancel' });
  }
}
