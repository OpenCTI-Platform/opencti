import { Page } from '@playwright/test';
import AutocompleteFieldPageModel from '../field/AutocompleteField.pageModel';

export default class ParticipantsFormPage {
  private readonly formLocator;

  participantsAutocomplete;

  constructor(private page: Page) {
    this.formLocator = this.page.getByRole('heading', { name: 'Add new participants' }).locator('..');
    this.participantsAutocomplete = new AutocompleteFieldPageModel(this.page, 'Participant(s)', true, this.formLocator);
  }

  getAddButton() {
    return this.page.getByRole('button', { name: 'Add', exact: true });
  }

  getCloseButton() {
    return this.page.getByRole('button', { name: 'Close', exact: true });
  }
}
