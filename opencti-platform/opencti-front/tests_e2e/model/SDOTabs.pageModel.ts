import { Page } from '@playwright/test';

/**
 * Common page for all components that have Overview/Knowledge/...etc tabs (in knowledge)
 */
export default class SDOTabs {
  constructor(private page: Page) {}

  goToOverviewTab() {
    return this.page.getByRole('tab', { name: 'Overview' }).click();
  }

  goToKnowledgeTab() {
    return this.page.getByRole('tab', { name: 'Knowledge' }).click();
  }

  goToEntitiesTab() {
    return this.page.getByRole('tab', { name: 'Entities' }).click();
  }

  goToContentTab() {
    return this.page.getByRole('tab', { name: 'Content' }).click();
  }

  goToDataTab() {
    return this.page.getByRole('tab', { name: 'Data' }).click();
  }

  goToObservablesTab() {
    return this.page.getByRole('tab', { name: 'Observables' }).click();
  }

  goToHistoryTab() {
    return this.page.getByRole('tab', { name: 'History' }).click();
  }
}
