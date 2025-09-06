import { Page } from '@playwright/test';

export default class PirTabsPage {
  constructor(private page: Page) {}

  goToOverviewTab() {
    return this.page.getByRole('tab', { name: 'Overview' }).click();
  }

  goToThreatsTab() {
    return this.page.getByRole('tab', { name: 'Threats' }).click();
  }

  goToAnalysesTab() {
    return this.page.getByRole('tab', { name: 'Analyses' }).click();
  }

  goToActivitiesTab() {
    return this.page.getByRole('tab', { name: 'Activities' }).click();
  }
}
