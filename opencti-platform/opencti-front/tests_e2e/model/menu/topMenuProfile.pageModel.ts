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
    await this.getMenuProfile().click();
    return this.getLogoutButton().click();
  }
}
