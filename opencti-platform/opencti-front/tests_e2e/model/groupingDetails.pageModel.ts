import { Page } from '@playwright/test';

export default class GroupingDetailsPage {
  constructor(private page: Page) {}

  getGroupingDetailsPage() {
    return this.page.getByTestId('grouping-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  goToTab(name: string) {
    return this.page.getByRole('tab', { name }).click();
  }
}
