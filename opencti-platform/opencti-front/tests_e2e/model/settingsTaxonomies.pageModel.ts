import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class SettingsTaxonomiesPage {
  pageUrl = '/dashboard/settings/vocabularies/labels';

  constructor(private page: Page) {
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Settings');
    await leftBarPage.getSubItem('Taxonomies');
  }

  async navigateRightMenu(menu: string) {
    await this.page.getByRole('menuitem', { name: menu, exact: true }).click();
  }

  getTaxonomiesPages(name: string) {
    return this.page.getByTestId(name);
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }
}
