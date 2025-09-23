import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class SettingsFiligranExperiencePage {
  pageUrl = '/dashboard/settings/experience';

  constructor(private page: Page) {
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Settings');
    await leftBarPage.getSubItem('Filigran Experience');
  }

  getPage(name: string) {
    return this.page.getByTestId(name);
  }
}
