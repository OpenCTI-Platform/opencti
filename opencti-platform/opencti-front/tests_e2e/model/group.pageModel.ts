import { Page } from '@playwright/test';

export default class GroupPage {
  constructor(private page: Page) {}

  getEditButton() {
    return this.page.getByLabel('Update');
  }

  getPage() {
    return this.page.getByTestId('group-details-page');
  }
}
