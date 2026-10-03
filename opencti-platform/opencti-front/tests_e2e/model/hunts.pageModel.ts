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

  getCreateButton() {
    return this.page.getByTestId('create-hunt-button');
  }

  openCreateForm() {
    return this.getCreateButton().click();
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }
}
