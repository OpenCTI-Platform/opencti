import { Page } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';

export default class TopMenuProfilePage {
  constructor(private page: Page) {}

  getMenuProfile() {
    return this.page.getByLabel('Profile');
  }

  getLogoutButton() {
    return this.page.getByRole('menuitem', { name: 'Logout' });
  }

  async logout() {
    const profileButton = this.getMenuProfile();
    const loginPage = this.page.getByTestId('login-page');
    await expect(profileButton.or(loginPage)).toBeVisible();
    if (await loginPage.isVisible()) return;
    await profileButton.click();
    await this.getLogoutButton().click();
    await expect(loginPage).toBeVisible();
  }
}
