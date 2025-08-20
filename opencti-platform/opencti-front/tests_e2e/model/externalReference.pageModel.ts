import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class ExternalReferencePage {
  pageUrl = '/dashboard/analyses/external_references';
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
    await leftBarPage.clickOnMenu('Analyses', 'External references');
  }

  getItemFromListWithUrl(name: string) {
    return this.page.getByRole('link', { name }).click();
  }

  getPage() {
    return this.page.getByTestId('external-reference-page');
  }

  addNew() {
    return this.getCreateExternalReferenceButton().click();
  }

  closeNew() {
    return this.page.getByLabel('Close', { exact: true }).click();
  }

  getCreateExternalReferenceButton() {
    return this.page.getByRole('button', { name: 'Create External reference' });
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name).first();
  }
}
