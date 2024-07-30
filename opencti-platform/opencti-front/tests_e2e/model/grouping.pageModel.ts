import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class GroupingsPage {
  pageUrl = '/dashboard/analyses/groupings';
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
    await leftBarPage.clickOnMenu('Analyses', 'Groupings');
  }

  getPage() {
    return this.page.getByTestId('groupings-page');
  }

  addNew() {
    return this.getCreateButton().click();
  }

  closeNew() {
    return this.page.getByLabel('Close', { exact: true }).click();
  }

  getNameInput() {
    return this.page.getByLabel('Name');
  }

  getCreateButton() {
    return this.page.getByRole('button', { name: 'Create Grouping' });
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name).first();
  }
}
