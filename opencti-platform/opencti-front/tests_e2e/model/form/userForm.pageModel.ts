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

  getEmailInput() {
    return this.page.getByTestId('user-creation-email-address-input').getByLabel('Email address');
  }

  async fillEmailInput(email: string) {
    await this.getEmailInput().click();
    return this.getEmailInput().fill(email);
  }

  getPasswordInput() {
    return this.page.getByTestId('user-creation-password-input').getByLabel('Password');
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
