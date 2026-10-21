import { Page } from '@playwright/test';

/**
 * Time machine of an entity (Changes tab: compare dates and view as of) and the landscape changes page.
 */
export default class TimeMachinePage {
  constructor(private page: Page) {}

  async openViewAsOfFromMenu() {
    // The header popover comes first in the page
    await this.page.getByRole('button', { name: 'Popover of actions' }).first().click();
    return this.page.getByRole('menuitem', { name: 'View as of' }).click();
  }

  getAsOfSection() {
    return this.page.getByTestId('time-machine-as-of');
  }

  getSlider() {
    return this.page.getByTestId('time-machine-slider');
  }

  getNotExistingMessage() {
    return this.page.getByTestId('time-machine-not-existing');
  }

  getAsOfView() {
    return this.page.getByTestId('time-machine-as-of-view');
  }

  backToCurrentKnowledge() {
    return this.getAsOfSection().getByRole('button', { name: 'Back to the current knowledge' }).click();
  }

  goToChangesTab() {
    return this.page.getByRole('tab', { name: 'Changes', exact: true }).click();
  }

  getChangesTab() {
    return this.page.getByTestId('entity-changes-tab');
  }

  goToChangesSection(name: 'Compare dates' | 'View as of') {
    return this.getChangesTab().getByRole('tab', { name, exact: true }).click();
  }

  getDiff() {
    return this.page.getByTestId('time-machine-diff');
  }

  getPeriodSelector() {
    return this.page.getByTestId('time-machine-period');
  }

  async exportDiff(menuItem: string) {
    // The export sits in the period toolbar, on the right of the period selector
    await this.getPeriodSelector().getByRole('button', { name: 'Export' }).click();
    return this.page.getByRole('menuitem', { name: menuItem }).click();
  }

  getLandscapeChangesPage() {
    return this.page.getByTestId('landscape-changes-page');
  }

  async selectLandscapeEntityType(label: string) {
    await this.getLandscapeChangesPage().getByRole('combobox', { name: 'Entity types' }).click();
    return this.page.getByRole('option', { name: label, exact: true }).click();
  }

  computeLandscapeChanges() {
    return this.page.getByTestId('landscape-changes-compute').click();
  }

  getLandscapeChangesResults() {
    return this.page.getByTestId('landscape-changes-results');
  }

  getLandscapeEntities() {
    return this.page.getByTestId('landscape-entities');
  }
}
