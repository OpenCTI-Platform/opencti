import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class SettingsSecurityPage {
  pageUrl = '/dashboard/settings/accesses/roles';

  constructor(private page: Page) {
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Settings');
    await leftBarPage.getSubItem('Security');
  }

  async navigateRightMenu(menu: string) {
    await this.page.getByRole('menuitem', { name: menu, exact: true }).click();
  }

  getSecurityPages(name: string) {
    return this.page.getByTestId(name);
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }
}
