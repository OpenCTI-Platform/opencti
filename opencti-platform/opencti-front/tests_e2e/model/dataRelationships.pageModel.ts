import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class DataRelationshipsPage {
  pageUrl = '/dashboard/data/relationships';

  constructor(private page: Page) {
  }

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Data', 'Relationships');
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }

  getPage() {
    return this.page.getByTestId('data-relationships-page');
  }
}
