import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class CampaignDetailsPage {
  tabs: SDOTabs;

  constructor(private page: Page) {
    this.tabs = new SDOTabs(this.page);
  }

  getPage() {
    return this.page.getByTestId('campaign-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }
}
