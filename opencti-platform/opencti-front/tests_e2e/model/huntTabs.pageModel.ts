import { Page } from '@playwright/test';

export default class HuntTabsPage {
  constructor(private page: Page) {}

  goToOverviewTab() {
    return this.page.getByRole('tab', { name: 'Overview' }).click();
  }

  goToLogicTab() {
    return this.page.getByRole('tab', { name: 'Logic' }).click();
  }

  goToRunsTab() {
    return this.page.getByRole('tab', { name: 'Runs' }).click();
  }

  goToEvidenceTab() {
    return this.page.getByRole('tab', { name: 'Evidence' }).click();
  }

  goToCoverageTab() {
    return this.page.getByRole('tab', { name: 'Coverage' }).click();
  }

  goToHistoryTab() {
    return this.page.getByRole('tab', { name: 'History' }).click();
  }
}
