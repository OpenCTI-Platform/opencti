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
// Bounds a single attempt of the menu navigation, so a step taken on a stale layout is
// abandoned and retried instead of consuming the whole budget of the retry loop.
const STEP_TIMEOUT = 10_000;
const NAVIGATION_TIMEOUT = 60_000;

export default class LeftBarPage {
  constructor(private page: Page) {}

  private nav(): Locator {
    return this.page.getByLabel('Main navigation', { exact: true });
  }

  async open() {
    await this.nav().hover();
    const expandButton = this.nav().getByRole('button', { name: 'Expand', exact: true });
    const collapseButton = this.nav().getByRole('button', { name: 'Collapse', exact: true });
    // Wait for one of the two states to be reachable before probing with the
    // non-waiting count(): a modal that is still closing marks the rest of the
    // page aria-hidden, and role queries answer 0 while that lasts.
    await expect(expandButton.or(collapseButton)).toBeVisible();
    if (await expandButton.count() > 0) {
      await expandButton.click();
      // The rail animates its width; wait for the expanded-only label to settle.
      await expect(collapseButton).toBeVisible();
    }
  }

  async clickOnMenu(menuName: string, subMenuItem?: string) {
    // The same row is an accordion trigger (button) when the rail is expanded
    // and an anchor when it is collapsed; both carry aria-expanded, so the role
    // is the only reliable discriminator. Wait for either before probing with
    // the non-waiting count(): a modal that is still closing marks the rest of
    // the page aria-hidden, and role queries answer 0 while that lasts.
    const trigger = this.nav().getByRole('button', { name: menuName, exact: true });
    const anchor = this.nav().getByRole('link', { name: menuName, exact: true });
    await expect(trigger.or(anchor)).toBeVisible();

    if (await trigger.count() === 0) {
      // Collapsed rail: the parent navigates on click and its children only
      // exist in the hover flyout, which the library portals out of the <nav>
      // and where Radix overrides the anchors' role to menuitem.
      if (subMenuItem) {
        await anchor.hover();
        const flyoutSub = this.page.getByRole('menuitem', { name: subMenuItem, exact: true });
        await expect(flyoutSub.first()).toBeVisible();
        await flyoutSub.first().click();
        return;
      }
      await anchor.click();
      return;
    }

    // Opening an already-open submenu would close it, which is what forced the
    // previous "open another menu first" dance. aria-expanded lets us simply
    // not click when it is already open.
    if (await trigger.getAttribute('aria-expanded') !== 'true') {
      await trigger.click();
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
