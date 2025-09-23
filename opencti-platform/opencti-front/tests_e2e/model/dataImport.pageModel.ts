import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class ImportPage {
  pageUrl = '/dashboard/data/import/file';

  constructor(private page: Page) {
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Data');
    await leftBarPage.getSubItem('Import');
  }

  async navigateBreadcrumbs(menu: string) {
    await this.page.getByRole('tab', { name: menu, exact: true }).click();
  }

  getImportPages(name: string) {
    return this.page.getByTestId(name);
  }
}
