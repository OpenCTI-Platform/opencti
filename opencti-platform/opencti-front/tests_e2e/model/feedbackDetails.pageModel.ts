import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class FeedbackDetailsPage {
  tabs: SDOTabs;

  constructor(private page: Page) {
    this.tabs = new SDOTabs(this.page);
  }

  getPage() {
    return this.page.getByTestId('feedback-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }
}
