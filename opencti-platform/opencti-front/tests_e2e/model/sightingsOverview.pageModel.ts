import { Page } from '@playwright/test';

export default class SightingsOverviewPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('sightings-overview');
  }
}
