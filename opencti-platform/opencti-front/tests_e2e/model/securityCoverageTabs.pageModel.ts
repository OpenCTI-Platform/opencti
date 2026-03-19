import { Page } from '@playwright/test';

export default class SecurityCoverageTabsPage {
  constructor(private page: Page) {}

  goToOverviewTab() {
    return this.page.getByRole('tab', { name: 'Overview' }).click();
  }

  goToResultTab() {
    return this.page.getByRole('tab', { name: 'Result' }).click();
  }

  goToContentTab() {
    return this.page.getByRole('tab', { name: 'Content' }).click();
  }

  goToDataTab() {
    return this.page.getByRole('tab', { name: 'Data' }).click();
  }

  goToHistoryTab() {
    return this.page.getByRole('tab', { name: 'History' }).click();
  }
}
