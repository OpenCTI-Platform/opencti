import { Page } from '@playwright/test';

export default class UserFormPage {
  constructor(private page: Page) {}

  getNameInput() {
    return this.page.getByRole('textbox', { name: 'Name', exact: true });
  }

  async fillNameInput(name: string) {
    await this.getNameInput().click();
    return this.getNameInput().fill(name);
  }

  // No `.getByLabel(...)` hop on either of these: the pivot forwards `data-*`
  // to the library Input, which places everything but `className` on the
  // native <input>. The test id IS the input now, where MUI put it on the
  // field's root wrapper and the descendant lookup was needed.
  getEmailInput() {
    return this.page.getByTestId('user-creation-email-address-input');
  }

  async fillEmailInput(email: string) {
    await this.getEmailInput().click();
    return this.getEmailInput().fill(email);
  }

  getPasswordInput() {
    return this.page.getByTestId('user-creation-password-input');
  }

  async fillPasswordInput(password: string) {
    await this.getPasswordInput().click();
    return this.getPasswordInput().fill(password);
  }

  getPasswordConfirmationInput() {
    return this.page.getByRole('textbox', { name: 'Confirmation' });
  }

  async fillPasswordConfirmationInput(passwordConfirmation: string) {
    await this.getPasswordConfirmationInput().click();
    return this.getPasswordConfirmationInput().fill(passwordConfirmation);
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  getGroupsTab() {
    return this.page.getByRole('tab', { name: 'Groups' });
  }

  getSpecificGroupCheckbox(groupName: string) {
    return this.page.locator('li').filter({ hasText: groupName }).getByRole('checkbox');
  }
}
