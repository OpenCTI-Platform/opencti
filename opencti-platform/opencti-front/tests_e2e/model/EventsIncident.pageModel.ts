import { Page } from '@playwright/test';

export default class EventsIncidentPage {
  pageUrl = '/dashboard/events/incidents';
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  getPage() {
    return this.page.getByTestId('incident-page');
  }
}
