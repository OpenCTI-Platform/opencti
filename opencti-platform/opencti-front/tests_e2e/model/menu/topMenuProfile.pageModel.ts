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

  /**
   * Logs out and waits for the login page. The whole sequence is retried, with a reload between
   * attempts: a page with in-flight requests can miss the redirect to the login page once its
   * session is gone, and would otherwise wait on it until the test timeout.
   */
  async logout(timeout = 30000) {
    const profileButton = this.getMenuProfile();
    const loginPage = this.page.getByTestId('login-page');
    let attempt = 0;
    await expect(async () => {
      if (attempt > 0) await this.page.reload({ waitUntil: 'domcontentloaded', timeout: 30000 });
      attempt += 1;
      await expect(profileButton.or(loginPage)).toBeVisible({ timeout });
      if (await loginPage.isVisible()) return;
      await profileButton.click({ timeout });
      await this.getLogoutButton().click({ timeout });
      await expect(loginPage).toBeVisible({ timeout });
    }).toPass({ timeout: timeout * 6, intervals: [1000] });
  }
}
