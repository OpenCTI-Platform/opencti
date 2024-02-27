// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';

export default class LeftBarPage {
  constructor(private page:Page) {}

  async clickOnMenu(menuName: string, subMenuItem?: string) {
    await this.page.getByRole('menuitem', { name: menuName }).click();
    if (subMenuItem) {
      await this.page.getByRole('menuitem', { name: subMenuItem }).click();
    }
  }

  async expectPage(menuName: string, pageName: string) {
    await this.page.getByRole('menuitem', { name: pageName }).click();
    await expect(this.page.getByText(`${menuName}/${pageName}`)).toBeVisible();
  }
}
