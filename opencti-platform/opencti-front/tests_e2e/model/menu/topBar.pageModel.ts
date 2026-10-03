import { Locator, Page } from '@playwright/test';

/**
 * Page object for the top bar.
 *
 * Anchored on what the design-system Header emits: a <header> landmark (role
 * banner) holding icon links named by their aria-label, and a profile menu
 * button opening a Radix menu whose entries are menu items.
 */
export default class TopBarPage {
  constructor(private page: Page) {}

  private header(): Locator {
    return this.page.getByRole('banner');
  }

  async clickOnIconLink(name: string) {
    await this.header().getByRole('link', { name, exact: true }).click();
  }

  async openProfileMenu() {
    await this.header().getByRole('button', { name: 'Profile', exact: true }).click();
  }

  async clickOnProfileMenuItem(name: string) {
    await this.page.getByRole('menuitem', { name, exact: true }).click();
  }
}
