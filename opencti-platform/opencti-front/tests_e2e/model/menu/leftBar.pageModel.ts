import { Page } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';

// Bounds a single attempt of the menu navigation, so a step taken on a stale layout is
// abandoned and retried instead of consuming the whole budget of the retry loop.
const STEP_TIMEOUT = 10_000;
const NAVIGATION_TIMEOUT = 60_000;

export default class LeftBarPage {
  constructor(private page: Page) {}

  async open() {
    await this.page.getByLabel('Main navigation', { exact: true }).hover();
    const isOpenButtonVisible = await this.page.getByTestId('ChevronRightIcon').isVisible();
    if (isOpenButtonVisible) {
      await this.page.getByTestId('ChevronRightIcon').click();
      await expect(this.page.getByTestId('ChevronLeftIcon')).toBeVisible();
    }
  }

  async clickOnMenu(menuName: string, subMenuItem?: string) {
    // Fix the following issue: if the menu to open is already open, and you
    // click on it then you are closing it and by so you do not have access
    // to the submenus anymore.
    // Here to be sure we are opening the menu instead of closing it, we open
    // an other one before, as we can have only one menu open at a time.
    const otherMenu = menuName === 'Threats' ? 'Arsenal' : 'Threats';
    const otherMenuLocator = this.page.getByTestId(`nav-button-${otherMenu.toLowerCase()}`);
    const menuLocator = this.page.getByTestId(`nav-button-${menuName.toLowerCase()}`);

    if (!subMenuItem) {
      await otherMenuLocator.click();
      await menuLocator.click();
      return;
    }

    // Expanding a menu collapses the previous one, so two collapses are animated at once and
    // the navigation container overflows, scrolls, then snaps back when the animation ends.
    // A sub menu item can therefore move between the actionability check and the click, and
    // the click silently lands on the neighbouring row without navigating anywhere.
    // Retry the whole sequence - reopening the menu from a known state on each attempt -
    // until the navigation actually happened.
    const subMenuItemLocator = this.page.getByTestId(`sub-menu-${subMenuItem.toLowerCase()}`);
    await expect(async () => {
      await otherMenuLocator.click({ timeout: STEP_TIMEOUT });
      await menuLocator.click({ timeout: STEP_TIMEOUT });
      await expect(subMenuItemLocator).toBeVisible({ timeout: STEP_TIMEOUT });

      const href = await subMenuItemLocator.getAttribute('href', { timeout: STEP_TIMEOUT });
      if (!href) {
        throw new Error(`The "${subMenuItem}" menu item is expected to be a link`);
      }
      // Resolved against the current location so an absolute href is compared on equal terms.
      const link = new URL(href, this.page.url()).pathname;

      await subMenuItemLocator.click({ timeout: STEP_TIMEOUT });
      const { pathname } = new URL(this.page.url());
      const hasNavigated = pathname === link || pathname.startsWith(`${link}/`);
      expect(hasNavigated, `Expected to navigate to "${link}" but current path is "${pathname}"`).toBeTruthy();
    }).toPass({ timeout: NAVIGATION_TIMEOUT });
  }

  async getSubItem(subMenuItem: string) {
    expect(await this.page.getByTestId(`sub-menu-${subMenuItem.toLowerCase()}`).isVisible());
    await this.page.getByTestId(`sub-menu-${subMenuItem.toLowerCase()}`).click();
  }

  async expectBreadcrumb(...items: string[]) {
    return expect(this.page.getByTestId('navigation').getByText(items.join('/'))).toBeVisible();
  }
}
