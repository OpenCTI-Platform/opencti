import { Page } from '@playwright/test';

export default class TrashPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('trash-page');
  }

  getTrashEntry(name: string) {
    return this.page.getByRole('button', { name });
  }
}
