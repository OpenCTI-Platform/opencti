import { Page } from '@playwright/test';

export default class StixCoreObjectDataAndHistoryTab {
  constructor(private page: Page) {
  }

  getPage() {
    return this.page.getByTestId('sco-data-file-and-history');
  }
}
