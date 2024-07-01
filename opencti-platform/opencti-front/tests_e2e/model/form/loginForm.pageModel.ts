import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class LoginFormPageModel {
  nameField = new TextFieldPageModel(this.page, 'Login', 'text');
  passwordField = new TextFieldPageModel(this.page, 'Password', 'text');

  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('login-page');
  }

  getSignInButton() {
    return this.page.getByRole('button', { name: 'Sign in' });
  }

  async login(name?: string, pwd?: string) {
    await this.nameField.fill(name ?? 'admin@opencti.io');
    await this.passwordField.fill(pwd ?? 'admin');
    return this.getSignInButton().click();
  }
}
