import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class CaseRftPage {
  constructor(private page: Page) {}

  getCaseRftFormCreate() {
    return this.page.getByRole('button', { name: 'Create a request for takedown' });
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }

  getPage() {
    return this.page.getByTestId('rft-page');
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Cases', 'Requests for takedown');
  }
}
