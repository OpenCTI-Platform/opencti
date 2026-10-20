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

  async login(name?: string, pwd?: string, options: { expectPasswordChange?: boolean } = {}) {
    await this.nameField.fill(name ?? 'admin@opencti.io');
    await this.passwordField.fill(pwd ?? 'admin');
    await this.getSignInButton().click();
    if (options.expectPasswordChange) {
      await expect(this.page.getByLabel('New password', { exact: true })).toBeVisible();
      await expect(this.page.getByLabel('Confirmation', { exact: true })).toBeVisible();
      return;
    }
    // The login form can already be displayed at a dashboard URL. Wait for the
    // authenticated shell after LoginForm.tsx's reload, not just the URL.
    await this.page.waitForURL('**/dashboard**');
    // Under load the shell's root query can fail and leave the app on its spinner for good: a reload
    // re-issues it. The first attempt only waits (the login's own reload may still be in flight and
    // must not be interrupted); each later attempt reloads first.
    const profile = new TopMenuProfilePage(this.page).getMenuProfile();
    let attempt = 0;
    await expect(async () => {
      if (attempt > 0) await this.page.reload({ waitUntil: 'domcontentloaded' });
      attempt += 1;
      await expect(profile).toBeVisible({ timeout: 45000 });
    }).toPass({ timeout: 180000, intervals: [1000] });
  }
}
