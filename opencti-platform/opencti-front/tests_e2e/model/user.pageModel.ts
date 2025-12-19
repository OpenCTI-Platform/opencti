import { Page } from '@playwright/test';

export default class UserPage {
  constructor(private page: Page) {}

  getEditButton() {
    return this.page.getByLabel('Update');
  }
}
