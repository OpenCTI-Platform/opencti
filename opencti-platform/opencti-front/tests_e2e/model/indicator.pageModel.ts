import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class IndicatorPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('indicator-page');
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Observations', 'Indicators');
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }
}
