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
    if (subMenuItem) {
      // Only open the parent menu if the submenu is not already visible,
      // otherwise clicking the parent would close it instead of opening it.
      const subMenuItemLocator = this.page.getByRole('menuitem', { name: subMenuItem });
      if (!await subMenuItemLocator.isVisible()) {
        await this.page.getByRole('menuitem', { name: menuName, exact: true }).click();
      }
      await subMenuItemLocator.click();
    } else {
      await this.page.getByRole('menuitem', { name: menuName, exact: true }).click();
    }
  }

  async getSubItem(subMenuItem: string) {
    await this.page.getByLabel(subMenuItem, { exact: true }).click();
  }

  async expectBreadcrumb(...items: string[]) {
    return expect(this.page.getByTestId('navigation').getByText(items.join('/'))).toBeVisible();
  }
}
