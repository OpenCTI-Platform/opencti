import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class ObservedDataPage {
  pageUrl = '/dashboard/events/observed_data';
  constructor(private page: Page) {}

  /**
   * Reload the page (like F5), mostly used once on test start.
   * When possible please use navigateFromMenu instead it's faster.
   */
  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Events', 'Observed data');
  }

  getPage() {
    return this.page.getByTestId('observed-data');
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name).first();
  }
}
