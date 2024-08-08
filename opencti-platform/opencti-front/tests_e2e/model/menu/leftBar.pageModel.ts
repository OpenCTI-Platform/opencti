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
    // Fix the following issue: if the menu to open is already open, and you
    // click on it then you are closing it and by so you do not have access
    // to the submenus anymore.
    // Here to be sure we are opening the menu instead of closing it, we open
    // an other one before, as we can have only one menu open at a time.
    const otherMenu = menuName === 'Threats' ? 'Arsenal' : 'Threats';
    await this.page.getByRole('menuitem', { name: otherMenu, exact: true }).click();

    await this.page.getByRole('menuitem', { name: menuName, exact: true }).click();
    if (subMenuItem) {
      await this.page.getByRole('menuitem', { name: subMenuItem }).click();
    }
  }

  async expectPage(menuName: string, pageName: string) {
    await this.page.getByRole('menuitem', { name: pageName, exact: true }).click();
    await expect(this.page.getByText(`${menuName}/${pageName}`)).toBeVisible();
  }
}
