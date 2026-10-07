import { Page } from '@playwright/test';

export default class TopMenuProfilePage {
  constructor(private page: Page) {}

  getMenuProfile() {
    return this.page.getByLabel('Profile');
  }

  getLogoutButton() {
    return this.page.getByRole('menuitem', { name: 'Logout' });
  }

  async logout(timeout?: number) {
    await this.getMenuProfile().click({ timeout });
    return this.getLogoutButton().click({ timeout });
  }
}
