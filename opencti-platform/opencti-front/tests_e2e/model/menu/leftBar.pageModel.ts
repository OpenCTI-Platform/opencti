import { Page, Locator } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';

/**
 * Page object for the main left navigation.
 *
 * Re-anchored on what the design-system Navbar actually emits rather than on
 * implementation details of the component it replaced:
 *  - the rail is a <nav aria-label="Main navigation">;
 *  - leaf entries and submenu entries are real anchors, so role=link;
 *  - a submenu parent is an accordion trigger, so role=button + aria-expanded,
 *    which lets us open a submenu idempotently instead of the previous
 *    "click another menu first" workaround;
 *  - the collapse toggle is the library's own row, named Expand/Collapse.
 *
 * The public method names and signatures are unchanged: 20 spec files call
 * them and this migration must not ripple into them.
 */
export default class LeftBarPage {
  constructor(private page: Page) {}

  private nav(): Locator {
    return this.page.getByLabel('Main navigation', { exact: true });
  }

  async open() {
    await this.nav().hover();
    const expandButton = this.nav().getByRole('button', { name: 'Expand', exact: true });
    if (await expandButton.isVisible()) {
      await expandButton.click();
      // The rail animates its width; wait for the expanded-only label to settle.
      await expect(this.nav().getByRole('button', { name: 'Collapse', exact: true })).toBeVisible();
    }
  }

  async clickOnMenu(menuName: string, subMenuItem?: string) {
    const parent = this.nav().getByRole('button', { name: menuName, exact: true });
    if (await parent.count() > 0) {
      // Opening an already-open submenu would close it, which is what forced
      // the previous "open another menu first" dance. aria-expanded lets us
      // simply not click when it is already open.
      if (await parent.getAttribute('aria-expanded') !== 'true') {
        await parent.click();
      }
    } else {
      await this.nav().getByRole('link', { name: menuName, exact: true }).click();
    }
    if (subMenuItem) {
      const sub = this.nav().getByRole('link', { name: subMenuItem, exact: true });
      await expect(sub).toBeVisible();
      await sub.click();
    }
  }

  async getSubItem(subMenuItem: string) {
    await this.nav().getByRole('link', { name: subMenuItem, exact: true }).click();
  }

  async expectBreadcrumb(...items: string[]) {
    return expect(this.page.getByTestId('navigation').getByText(items.join('/'))).toBeVisible();
  }
}
