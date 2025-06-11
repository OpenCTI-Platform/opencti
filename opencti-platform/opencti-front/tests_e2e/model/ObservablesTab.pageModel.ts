import { Page } from '@playwright/test';

export default class ObservablesTabPageModel {
  constructor(private page: Page) {}

  clickAddObservables() {
    return this.page.getByLabel('Add', { exact: true }).click();
  }

  addObservable(name: string) {
    const parent = this.page.getByRole('heading', { name: 'Add entities' }).locator('../..');
    return parent.getByRole('button', { name }).click();
  }

  closeAddObservable() {
    const parent = this.page.getByRole('heading', { name: 'Add entities' }).locator('../..');
    return parent.getByLabel('Close').click();
  }

  gotToKnowledgeTab() {
    return this.page.getByRole('tab', { name: 'Knowledge' }).click();
  }

  goToContentTab() {
    return this.page.getByRole('tab', { name: 'Content' }).click();
  }

  goToAnalysesTab() {
    return this.page.getByRole('tab', { name: 'Analyses' }).click();
  }

  goToSightingsTab() {
    return this.page.getByRole('tab', { name: 'Sightings' }).click();
  }

  goToDataTab() {
    return this.page.getByRole('tab', { name: 'Data' }).click();
  }

  goToHistoryTab() {
    return this.page.getByRole('tab', { name: 'History' }).click();
  }
}
