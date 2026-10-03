import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class HuntsPage {
  pageUrl = '/dashboard/events/hunts';
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Events', 'Hunts');
  }

  getPage() {
    return this.page.getByTestId('hunts-page');
  }

  getCreateButton() {
    return this.page.getByTestId('create-hunt-button');
  }

  openCreateForm() {
    return this.getCreateButton().click();
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }
}
