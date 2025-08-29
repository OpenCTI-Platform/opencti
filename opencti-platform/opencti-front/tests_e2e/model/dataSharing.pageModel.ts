import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class SharingPage {
  pageUrl = '/dashboard/data/sharing/streams';

  constructor(private page: Page) {
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Data');
    await leftBarPage.getSubItem('Data sharing');
  }

  async navigateRightMenu(menu: string) {
    await this.page.getByRole('menuitem', { name: menu, exact: true }).click();
  }

  getDataSharingPages(name: string) {
    return this.page.getByTestId(name);
  }
}
