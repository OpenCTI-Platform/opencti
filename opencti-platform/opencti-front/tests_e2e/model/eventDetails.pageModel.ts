import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class EventDetailsPage {
  tabs = new SDOTabs(this.page);

  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('event-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }
}
