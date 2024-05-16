import { Page } from '@playwright/test';
import AutocompleteFieldPageModel from './field/AutocompleteField.pageModel';
import SelectFieldPageModel from './field/SelectField.pageModel';

export default class AccessRestrictionPageModel {
  private identityAutocomplete = new AutocompleteFieldPageModel(this.page, 'Users, groups or organizations', false);
  private accessSelect = new SelectFieldPageModel(this.page, 'Access right', false);

  constructor(private page: Page) {}

  openForm() {
    return this.page.getByRole('button', { name: 'Manage access restriction' }).click();
  }

  async addAccess(identity: string, level: 'can view' | 'can edit' | 'can manage') {
    await this.identityAutocomplete.selectOption(identity);
    await this.accessSelect.selectOption(level);
    return this.page.getByRole('button', { name: 'More' }).click();
  }

  editAccess(identity: string, level: 'can view' | 'can edit' | 'can manage') {
    const identityRow = this.page.getByText(identity).locator('../..');
    const select = new SelectFieldPageModel(this.page, '', false, identityRow);
    return select.selectOption(level);
  }

  deleteAccess(identity: string) {
    const identityRow = this.page.getByText(identity).locator('../..');
    return identityRow.getByRole('button', { name: 'Delete' }).click();
  }

  cancel() {
    return this.page.getByRole('button', { name: 'cancel' }).click();
  }

  save() {
    return this.page.getByRole('button', { name: 'save' }).click();
  }
}
