import { Page } from '@playwright/test';

export default class StixCoreObjectHistoryTab {
  constructor(private page: Page) {
  }

  getPage() {
    return this.page.getByTestId('sco-history-content');
  }
}
