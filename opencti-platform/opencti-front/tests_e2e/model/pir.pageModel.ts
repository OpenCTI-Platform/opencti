import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class PirPage {
  pageUrl = '/dashboard/pirs';
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('PIR');
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create PIR', exact: true });
  }

  openCreateForm() {
    return this.getCreateButton().click();
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }
}
