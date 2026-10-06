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

  async logout(timeout?: number) {
    const profileButton = this.getMenuProfile();
    const loginPage = this.page.getByTestId('login-page');
    await expect(profileButton.or(loginPage)).toBeVisible({ timeout });
    if (await loginPage.isVisible()) return;
    await profileButton.click({ timeout });
    await this.getLogoutButton().click({ timeout });
    await expect(loginPage).toBeVisible({ timeout });
  }
}
