import { Page } from '@playwright/test';

/**
 * Time machine of an entity (overview "View as of" mode and Diff tab) and the landscape changes page.
 */
export default class TimeMachinePage {
  constructor(private page: Page) {}

  getAsOfToggle() {
    return this.page.getByTestId('time-machine-toggle');
  }

  getAsOfOverview() {
    return this.page.getByTestId('time-machine-overview');
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
    return this.getAsOfOverview().getByRole('button', { name: 'Back to the current knowledge' }).click();
  }

  goToDiffTab() {
    return this.page.getByRole('tab', { name: 'Diff' }).click();
  }

  getDiff() {
    return this.page.getByTestId('time-machine-diff');
  }

  getPeriodSelector() {
    return this.page.getByTestId('time-machine-period');
  }

  async exportDiff(menuItem: string) {
    await this.getDiff().getByRole('button', { name: 'Export' }).click();
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
