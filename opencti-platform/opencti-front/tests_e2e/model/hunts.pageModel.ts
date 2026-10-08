import { Page } from '@playwright/test';

export default class HuntsPage {
  pageUrl = '/dashboard/defense/hunts';
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  getPage() {
    return this.page.getByTestId('hunts-page');
  }

  // The list header button, or the first-use hero when the platform holds no hunt yet
  getCreateButton() {
    return this.page.getByTestId('create-hunt-button').or(this.page.getByTestId('hunts-first-use-create'));
  }

  openCreateForm() {
    return this.getCreateButton().click();
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }
}
