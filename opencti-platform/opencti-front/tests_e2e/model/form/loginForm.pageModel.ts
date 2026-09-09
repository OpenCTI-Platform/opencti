import { Page } from '@playwright/test';
import TextFieldPageModel from '../field/TextField.pageModel';
import TopMenuProfilePage from '../menu/topMenuProfile.pageModel';
import { expect } from '../../fixtures/baseFixtures';

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
    // The login form can already be displayed at a dashboard URL. Wait for the
    // authenticated shell after LoginForm.tsx's reload, not just the URL.
    await this.page.waitForURL('**/dashboard**');
    await expect(new TopMenuProfilePage(this.page).getMenuProfile()).toBeVisible();
  }
}
