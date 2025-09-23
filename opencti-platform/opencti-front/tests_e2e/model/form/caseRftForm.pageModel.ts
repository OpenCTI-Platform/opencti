import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';

export default class CaseRftFormPage {
  private readonly formLocator;

  nameField;
  participantsAutocomplete;

  constructor(private page: Page, formTitle: string) {
    this.formLocator = this.page.getByRole('heading', { name: formTitle }).locator('../..');
    this.nameField = new TextFieldPageModel(this.page, 'Name', 'text', this.formLocator);
    this.participantsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Participant(s)', true, this.formLocator);
  }

  getCreateTitle() {
    return this.page.getByRole('heading', { name: 'Create a request for takedown' });
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  getCloseButton() {
    return this.page.getByRole('button', { name: 'Close' });
  }

  getCancelButton() {
    return this.page.getByRole('button', { name: 'Cancel' });
  }
}
