import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class CaseRfiPage {
  constructor(private page: Page) {}

  getCaseRfiFormCreate() {
    return this.page.getByRole('button', { name: 'Create request for information' });
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }

  getPage() {
    return this.page.getByTestId('rfis-page');
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Cases', 'Requests for information');
  }
}
