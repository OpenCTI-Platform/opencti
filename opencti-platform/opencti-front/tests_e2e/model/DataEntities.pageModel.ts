import { Page } from '@playwright/test';

export default class DataEntitiesPage {
  pageUrl = '/dashboard/data/entities';

  constructor(private page: Page) {
  }

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  getPage() {
    return this.page.getByTestId('data-entities-page');
  }
}
