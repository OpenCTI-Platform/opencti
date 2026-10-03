import { Page } from '@playwright/test';
import HuntTabsPage from './huntTabs.pageModel';
import SelectFieldPageModel from './field/SelectField.pageModel';

export default class HuntDetailsPage {
  tabs: HuntTabsPage;
  verdictField: SelectFieldPageModel;

  constructor(private page: Page) {
    this.tabs = new HuntTabsPage(this.page);
    this.verdictField = new SelectFieldPageModel(this.page, 'Your verdict', false, this.page.getByTestId('hunt-run-verdict-form'));
  }

  gotoRun(huntId: string, runId: string) {
    return this.page.goto(`/dashboard/defense/hunts/${huntId}/runs/${runId}`);
  }

  getPage() {
    return this.page.getByTestId('hunt-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getOverview() {
    return this.page.getByTestId('hunt-overview');
  }

  getLogicPage() {
    return this.page.getByTestId('hunt-logic-page');
  }

  getLogicSigmaEditor() {
    return this.getLogicPage().getByTestId('hunt-logic-sigma').locator('textarea');
  }

  getLogicSigmaValidation() {
    return this.getLogicPage().getByTestId('hunt-sigma-validation');
  }

  getLogicSaveButton() {
    return this.getLogicPage().getByTestId('hunt-logic-save');
  }

  getRunsPage() {
    return this.page.getByTestId('hunt-runs-page');
  }

  getEvidencePage() {
    return this.page.getByTestId('hunt-evidence-page');
  }

  getCoveragePage() {
    return this.page.getByTestId('hunt-coverage-page');
  }

  getRunVerdictForm() {
    return this.page.getByTestId('hunt-run-verdict-form');
  }

  getVerdictChip(label: string) {
    return this.page.getByTestId('hunt-verdict-chip').filter({ hasText: label }).first();
  }

  saveRunVerdict() {
    return this.page.getByTestId('hunt-run-verdict-submit').click();
  }

  async delete() {
    await this.page.getByRole('button', { name: 'Popover of actions' }).click();
    await this.page.getByRole('menuitem', { name: 'Delete' }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
  }
}
