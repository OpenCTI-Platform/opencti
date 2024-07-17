import { Page } from '@playwright/test';

export default class StixCoreObjectDataTab {
  constructor(private page: Page) {
  }

  getPage() {
    return this.page.getByTestId('sco-data-file-and-history');
  }
}
