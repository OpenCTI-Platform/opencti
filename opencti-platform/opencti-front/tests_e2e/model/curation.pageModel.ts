import { Page } from '@playwright/test';

export default class CurationPage {
  constructor(private page: Page) {}

  async gotoHub() {
    await this.page.goto('/dashboard/data/curation');
  }

  async gotoCustomization() {
    await this.page.goto('/dashboard/settings/customization/curation');
  }

  async gotoEntityMerges(entityPath: string) {
    await this.page.goto(`${entityPath}/changes?view=merges`);
  }

  getHubTab(path: 'inbox' | 'merges' | 'health') {
    return this.page.getByTestId(`curation-tab-${path}`);
  }

  getInbox() {
    return this.page.getByTestId('curation-proposals-page');
  }

  getMerges() {
    return this.page.getByTestId('curation-merge-records-page');
  }

  getKnowledgeHealth() {
    return this.page.getByTestId('knowledge-health-page');
  }

  getCustomization() {
    return this.page.getByTestId('curation-customization-page');
  }

  getCustomizationTab(tab: 'settings' | 'policies') {
    return this.page.getByTestId(`curation-customization-tab-${tab}`);
  }

  getSettings() {
    return this.page.getByTestId('curation-settings-page');
  }

  getPolicies() {
    return this.page.getByTestId('curation-policies-page');
  }

  getChangesTab() {
    return this.page.getByTestId('entity-changes-tab');
  }

  getEntityMerges() {
    return this.page.getByTestId('entity-merge-records');
  }

  getMergeRecordDetails() {
    return this.page.getByTestId('merge-record-details');
  }

  getUnmergeButton() {
    return this.page.getByTestId('merge-record-unmerge');
  }

  getUnmergeConfirmButton() {
    return this.page.getByTestId('merge-record-unmerge-confirm');
  }
}
