import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

/** The PIR list URL: it redirects to the intelligence requirement list (one PIR concept). */
export default class PirPage {
  pageUrl = '/dashboard/pirs';
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Intelligence requirements');
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }
}
