import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class SettingsCustomizationPage {
  pageUrl = '/dashboard/settings/customization/entity_types';

  constructor(private page: Page) {
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Settings');
    await leftBarPage.getSubItem('Customization');
  }

  async navigateRightMenu(menu: string) {
    await this.page.getByRole('menuitem', { name: menu, exact: true }).click();
  }

  getCustomizationPages(name: string) {
    return this.page.getByTestId(name);
  }

  getItemFromList(name: string) {
    return this.page.getByRole('link', { name });
  }
}
