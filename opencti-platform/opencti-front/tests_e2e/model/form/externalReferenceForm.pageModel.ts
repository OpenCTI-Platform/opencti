import { Locator, Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import FileFieldPageModel from '../field/FileField.pageModel';

export default class ExternalReferenceFormPageModel {
  private readonly formLocator: Locator;

  sourceNameField: TextFieldPageModel;
  externalIdField: TextFieldPageModel;
  urlField: TextFieldPageModel;
  associatedFileField: FileFieldPageModel;
  descriptionField: TextFieldPageModel;

  constructor(private page: Page) {
    this.formLocator = this.page.getByRole('heading', { name: 'Create an external reference' }).locator('../..');
    this.sourceNameField = new TextFieldPageModel(this.page, 'Source name', 'text-no-label', this.formLocator);
    this.externalIdField = new TextFieldPageModel(this.page, 'External ID', 'text', this.formLocator);
    this.urlField = new TextFieldPageModel(this.page, 'URL', 'text', this.formLocator);
    this.associatedFileField = new FileFieldPageModel(this.page, 'Associated file', this.formLocator);
    this.descriptionField = new TextFieldPageModel(this.page, 'Description', 'text-area', this.formLocator);
  }

  getCreateButton() {
    return this.formLocator.getByText('Create', { exact: true });
  }

  getCancelButton() {
    return this.formLocator.getByRole('button', { name: 'Cancel' });
  }
}
