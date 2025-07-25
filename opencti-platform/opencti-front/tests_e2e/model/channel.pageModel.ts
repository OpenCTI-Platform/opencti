import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class ChannelPage {
  constructor(private page: Page) {}

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }

  getPage() {
    return this.page.getByTestId('channel-page');
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Arsenal', 'Channels');
  }
}
