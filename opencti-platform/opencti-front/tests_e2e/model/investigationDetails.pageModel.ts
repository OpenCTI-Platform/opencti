import { Locator, Page } from '@playwright/test';

/** Border colour of a technique used in the investigation (`#b71c1c`, the matrix's highlight). */
export const MATRIX_HIGHLIGHT_BORDER_COLOR = 'rgb(183, 28, 28)';

export default class InvestigationDetailsPage {
  constructor(private page: Page) {
  }

  getInvestigationDetailsPage() {
    return this.page.getByTestId('investigation-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  openPopUpButton() {
    return this.page.getByLabel('Popover of actions');
  }

  getEditButton() {
    return this.page.getByRole('button', { name: 'Update' });
  }

  getDeleteButton() {
    return this.page.getByRole('button', { name: 'Delete' });
  }

  async delete() {
    await this.page.getByRole('button', { name: 'Popover of actions' }).click();
    await this.page.getByRole('menuitem', { name: 'Delete' }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
  }

  getConfirmButton() {
    return this.page.getByRole('button', { name: 'Confirm' });
  }

  addNewInvestigationTag() {
    return this.page.getByLabel('Add tag');
  }

  getTag(name: string) {
    return this.page.getByRole('button', { name });
  }

  // -- Graph / tactics matrix views

  getGraphViewLink() {
    return this.page.getByLabel('Graph view', { exact: true });
  }

  getMatrixViewLink() {
    return this.page.getByLabel('Tactics matrix view', { exact: true });
  }

  async goToMatrix() {
    await this.getMatrixViewLink().click();
  }

  async goToGraph() {
    await this.getGraphViewLink().click();
  }

  getMatrix() {
    return this.page.locator('#investigation-matrix-export');
  }

  /** A leaf technique cell of the investigation matrix, whose label reads `T9001 - E2E Alpha`. */
  getMatrixCell(label: string): Locator {
    return this.getMatrix().getByRole('button', { name: label });
  }

  getKillChainSelect(): Locator {
    return this.getMatrix().getByRole('combobox', { name: 'Kill chain' });
  }

  getKillChainOption(name: string): Locator {
    return this.page.getByRole('option', { name });
  }

  getOnlyUsedToggle(): Locator {
    return this.getMatrix().getByRole('button', { name: /^Display (only used techniques|the whole matrix)$/ });
  }

  getSecurityPostureSelect(): Locator {
    return this.getMatrix().getByRole('combobox', { name: 'Compare with my security posture' });
  }

  async selectSecurityPlatform(name: string) {
    await this.getSecurityPostureSelect().click();
    await this.getSecurityPostureSelect().fill(name);
    await this.page.getByRole('option', { name }).click();
  }

  getUnplacedNote() {
    return this.getMatrix().getByText(/attack patterns in this investigation aren't shown in this kill chain/);
  }

  getEmptyMatrixText() {
    return this.getMatrix().getByText('Add attack patterns to the graph view to visualise them here');
  }
}
