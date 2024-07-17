import { Page } from '@playwright/test';

export default class SearchPageModel {
  constructor(private page: Page) {}

  async addSearch(searchText: string) {
    await this.page.getByPlaceholder('Search these results...').click();
    await this.page.getByPlaceholder('Search these results...').pressSequentially(searchText, { delay: 100 });
    await this.page.getByPlaceholder('Search these results...').press('Enter');
  }
}
