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

  // -- Heatmap

  getHeatmapToggle(): Locator {
    return this.getMatrix().getByRole('button', { name: 'Displays heat map of attack pattern use' });
  }

  /**
   * The focusable wrapper of the heatmap toggle. When the toggle is disabled it takes no pointer event,
   * so its tooltip is opened through this element.
   */
  getHeatmapToggleWrapper(): Locator {
    return this.getHeatmapToggle().locator('xpath=..');
  }

  async toggleHeatmap() {
    await this.getHeatmapToggle().click();
  }

  /** The legend, one image for assistive technologies: its name is "Technique usage scale, 1 to N". */
  getLegend(): Locator {
    return this.getMatrix().getByRole('img', { name: /^Technique usage scale, 1 to \d+$/ });
  }

  /** One swatch of the legend, by its stop index (0 to 4). */
  getLegendSwatch(stop: number): Locator {
    return this.getLegend().locator(`[data-heat-stop="${stop}"]`);
  }

  /** The text of a cell, which carries the label colour of a filled cell. */
  getCellLabel(label: string): Locator {
    return this.getMatrixCell(label).getByText(label, { exact: true });
  }

  /** The sub-technique count badge of a parent technique (`n/m`), drawn over its accordion. */
  getBadgeOfCell(label: string): Locator {
    return this.getMatrixCell(label)
      .locator('xpath=ancestor::span[contains(@class, "MuiBadge-root")][1]')
      .locator('.MuiBadge-badge');
  }

  getTooltip(): Locator {
    return this.page.getByRole('tooltip');
  }

  /**
   * A parent technique with sub-techniques is an accordion: its border is on the accordion, not on the cell button.
   */
  getAccordionOfCell(label: string): Locator {
    return this.getMatrixCell(label).locator('xpath=ancestor::div[contains(@class, "MuiAccordion-root")][1]');
  }

  getExpandButton(label: string): Locator {
    return this.getMatrixCell(label).getByRole('button', { name: 'Expand' });
  }

  /**
   * The computed value of a CSS colour, resolved where the matrix is, so the theme variables
   * (`var(--yellow-300)`...) and `color-mix()` resolve exactly as they do for a cell.
   */
  async resolveColor(value: string, property: 'color' | 'backgroundColor'): Promise<string> {
    return this.getMatrix().evaluate((wrapper, args) => {
      const probe = document.createElement('div');
      probe.style[args.property] = args.value;
      wrapper.appendChild(probe);
      const resolved = getComputedStyle(probe)[args.property];
      probe.remove();
      return resolved;
    }, { value, property });
  }

  /** The widest scroll width in the matrix: the scroll box of the columns, not the viewport-wide wrapper. */
  async getMatrixScrollWidth(): Promise<number> {
    return this.getMatrix().evaluate((wrapper) => Math.max(
      wrapper.scrollWidth,
      ...Array.from(wrapper.querySelectorAll('*')).map((element) => element.scrollWidth),
    ));
  }

  // -- Header export (matrix view: it exports the matrix)

  getExportToImageButton(): Locator {
    return this.page.getByRole('button', { name: 'Export to image' });
  }

  getExportToPdfButton(): Locator {
    return this.page.getByRole('button', { name: 'Export to PDF' });
  }

  getExportImageMenuItem(theme: 'Dark' | 'Light'): Locator {
    return this.page.getByRole('menuitem', { name: `${theme} (with background)` });
  }

  getExportPdfMenuItem(theme: 'Dark' | 'Light'): Locator {
    return this.page.getByRole('menuitem', { name: theme, exact: true });
  }

  getUnplacedNote() {
    return this.getMatrix().getByText(/attack patterns? in this investigation (isn't|aren't) shown in this kill chain/);
  }

  getEmptyMatrixText() {
    return this.getMatrix().getByText('Add attack patterns to the graph view to visualise them here');
  }
}
