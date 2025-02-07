import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class ObservablesPage {
  pageUrl = '/dashboard/observations/observables';
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
    await leftBarPage.clickOnMenu('Observations', 'Observables');
  }

  getPage() {
    return this.page.getByTestId('observables-page');
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
    return this.page.getByRole('button', { name: 'Create Observable' });
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name).first();
  }
}
