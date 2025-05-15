import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class ObservedDataDetailsPage {
  tabs = new SDOTabs(this.page);
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('observed-data-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  goToTab(name: string) {
    return this.page.getByRole('tab', { name }).click();
  }
}
