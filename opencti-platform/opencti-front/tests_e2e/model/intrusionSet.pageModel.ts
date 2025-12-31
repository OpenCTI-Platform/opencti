import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class IntrusionSetPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('instrusion-set-page');
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Threats', 'Intrusion sets');
  }

  addNewIntrusionSet() {
    return this.page.getByLabel('Create Intrusion Set', { exact: true }).click();
  }

  getCreateIntrusionSetButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  getItemFromList(name: string) {
    return this.page.getByRole('link', { name }).first();
  }
}
