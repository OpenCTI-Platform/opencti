import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class InfrastructurePage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('infrastructures-page');
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Observations', 'Infrastructures');
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }
}
