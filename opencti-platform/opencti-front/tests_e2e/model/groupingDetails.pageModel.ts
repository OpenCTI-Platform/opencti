import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class GroupingDetailsPage {
  tabs: SDOTabs;
  constructor(private page: Page) {
    this.tabs = new SDOTabs(this.page);
  }

  getPage() {
    return this.page.getByTestId('grouping-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  goToTab(name: string) {
    return this.page.getByRole('tab', { name }).click();
  }
}
