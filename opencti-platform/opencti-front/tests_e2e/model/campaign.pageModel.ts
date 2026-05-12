import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class CampaignPageModel {
  constructor(private page: Page) {}

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }

  getItemFromListWithUrl(name: string) {
    return this.page.getByRole('link', { name });
  }

  getPage() {
    return this.page.getByTestId('campaign-page');
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Threats', 'Campaigns');
  }
}
