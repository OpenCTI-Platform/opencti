import { Page } from '@playwright/test';

export default class SearchPageModel {
  constructor(private page: Page) {}

  async addSearch(searchText: string) {
    await this.page.getByPlaceholder('Search these results...').click();
    await this.page.getByPlaceholder('Search these results...').pressSequentially(searchText, { delay: 100 });
    await this.page.getByPlaceholder('Search these results...').press('Enter');
  }

  /** Wrapping the query in double quotes triggers an exact-phrase match server-side, unlike the default loose word match. */
  async addExactSearch(searchText: string) {
    await this.addSearch(`"${searchText}"`);
  }

  /** The search term is persisted to localStorage (usePaginationLocalStorage) and restored by the list
   * on future navigations/reloads, so it must be explicitly cleared rather than just navigating away. */
  async clearSearch() {
    await this.page.getByPlaceholder('Search these results...').fill('');
    await this.page.getByPlaceholder('Search these results...').press('Enter');
  }
}
