import { Page } from '@playwright/test';

export default class RolePage {
  constructor(private page: Page) {}

  getEditButton() {
    return this.page.getByLabel('Update');
  }
}
