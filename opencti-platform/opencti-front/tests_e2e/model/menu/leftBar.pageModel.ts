import { Page } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';

export default class LeftBarPage {
  constructor(private page: Page) {}

  async open() {
    await this.page.getByLabel('Main navigation', { exact: true }).hover();
    const isOpenButtonVisible = await this.page.getByTestId('ChevronRightIcon').isVisible();
    if (isOpenButtonVisible) {
      await this.page.getByTestId('ChevronRightIcon').click();
    }
  }

  async clickOnMenu(menuName: string, subMenuItem?: string) {
    if (!subMenuItem) {
      // Fix the following issue: if the menu to open is already open, and you
      // click on it then you are closing it and by so you do not have access
      // to the submenus anymore.
      // Here to be sure we are opening the menu instead of closing it, we open
      // an other one before, as we can have only one menu open at a time.
      const otherMenu = menuName === 'Threats' ? 'Arsenal' : 'Threats';
      await this.page.getByRole('menuitem', { name: otherMenu, exact: true }).click();
      await this.page.getByRole('menuitem', { name: menuName, exact: true }).click();
      return;
    }

    // Only expand the parent menu when the sub menu item is not displayed yet. Toggling
    // menus back and forth animates two collapses at once, which makes the navigation
    // container overflow, scroll, then snap back when the animation ends: the sub menu
    // items move between the actionability check and the click, so the click silently
    // lands on another row.
    const subMenuItemLocator = this.page.getByRole('menuitem', { name: subMenuItem, exact: true });
    if (!(await subMenuItemLocator.isVisible())) {
      await this.page.getByRole('menuitem', { name: menuName, exact: true }).click();
      await expect(subMenuItemLocator).toBeVisible();
    }

    // The collapse is animated, so a click can still be delivered while the menu is
    // moving. Assert that the navigation did happen and click again if it did not,
    // instead of carrying on and failing much later on an unrelated page locator.
    const href = await subMenuItemLocator.getAttribute('href');
    if (!href) {
      throw new Error(`The "${subMenuItem}" menu item is expected to be a link`);
    }
    // Resolved against the current location so an absolute href is compared on equal terms.
    const link = new URL(href, this.page.url()).pathname;
    await expect(async () => {
      await subMenuItemLocator.click();
      const { pathname } = new URL(this.page.url());
      const hasNavigated = pathname === link || pathname.startsWith(`${link}/`);
      expect(hasNavigated, `Expected to navigate to "${link}" but current path is "${pathname}"`).toBeTruthy();
    }).toPass({ timeout: 30_000 });
  }

  async getSubItem(subMenuItem: string) {
    await this.page.getByLabel(subMenuItem, { exact: true }).click();
  }

  async expectBreadcrumb(...items: string[]) {
    return expect(this.page.getByTestId('navigation').getByText(items.join('/'))).toBeVisible();
  }
}
