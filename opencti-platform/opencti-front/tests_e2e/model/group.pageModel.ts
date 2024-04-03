// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';

export default class GroupPage {
  constructor(private page: Page) {}

  getEditButton() {
    return this.page.getByLabel('Edit');
  }
}
