import { Page } from '@playwright/test';

export default class TopMenuProfilePage {
  constructor(private page: Page) {}

  getMenuProfile() {
    return this.page.getByLabel('Profile');
  }

  getLogoutButton() {
    return this.page.getByRole('menuitem', { name: 'Logout' });
  }

  /**
   * @param timeout Bounds each click. A click that triggers a navigation only resolves once that
   *               navigation settles, so without a bound a logout whose redirect never completes
   *               holds the caller until the test timeout, with no artifact captured in a hook.
   */
  async logout(timeout?: number) {
    await this.getMenuProfile().click({ timeout });
    return this.getLogoutButton().click({ timeout });
  }
}
