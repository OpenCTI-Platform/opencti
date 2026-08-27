import { Page } from '@playwright/test';

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
    const isLoggedIn = await profileButton.waitFor({ state: 'visible', timeout: 5000 }).then(() => true).catch(() => false);
    if (!isLoggedIn) return; // already logged out
    await profileButton.click();
    await this.getLogoutButton().click();
  }
}
