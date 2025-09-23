import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class CampaignDetailsPage {
  tabs = new SDOTabs(this.page);

  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('campaign-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }
}
