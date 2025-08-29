import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class ProcessingPage {
  pageUrl = '/dashboard/data/processing/automation';

  constructor(private page: Page) {
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Data');
    await leftBarPage.getSubItem('Processing');
  }

  async navigateRightMenu(menu: string) {
    await this.page.getByRole('menuitem', { name: menu, exact: true }).click();
  }

  getProcessingPages(name: string) {
    return this.page.getByTestId(name);
  }
}
