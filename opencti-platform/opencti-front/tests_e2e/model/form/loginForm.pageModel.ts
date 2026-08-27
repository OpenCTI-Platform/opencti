import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';

export default class LoginFormPageModel {
  nameField: TextFieldPageModel;
  passwordField: TextFieldPageModel;

  constructor(private page: Page) {
    this.nameField = new TextFieldPageModel(this.page, 'Login', 'text');
    this.passwordField = new TextFieldPageModel(this.page, 'Password', 'text');
  }

  getPage() {
    return this.page.getByTestId('login-page');
  }

  getSignInButton() {
    return this.page.getByRole('button', { name: 'Sign in' });
  }

  async login(name?: string, pwd?: string) {
    await this.nameField.fill(name ?? 'admin@opencti.io');
    await this.passwordField.fill(pwd ?? 'admin');
    await this.getSignInButton().click();
    // LoginForm.tsx does `window.location.reload()` on success, then the authenticated
    // app client-side redirects '/' -> '/dashboard' (private/Root.tsx) - wait for that
    // full round-trip so a subsequent direct page.goto() doesn't race the pending reload.
    await this.page.waitForURL('**/dashboard**');
  }
}
