import { expect, Locator, Page } from '@playwright/test';
import type { InvestigationMatrixFilters } from '../../src/private/components/workspaces/investigations/matrix/matrixFilters';

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
    return this.page.getByLabel('Matrix view', { exact: true });
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

  /** A technique that counts `count` linked entities: its accessible name says so, as `T9001 - E2E Alpha, linked to 3 entities`. */
  getMatrixCellLinkedTo(label: string, count: number): Locator {
    return this.page.getByRole('button', { name: `${label}, linked to ${count} ${count === 1 ? 'entity' : 'entities'}`, exact: true });
  }

  // -- Matrix toolbar: docked under the matrix, it holds what the matrix view does (kill chain, display, heatmap, filters, posture, export)

  getMatrixToolbar(): Locator {
    return this.page.getByRole('toolbar', { name: 'Matrix toolbar' });
  }

  /** A button of the matrix toolbar; other buttons of the page (the header's) may carry the same name. */
  getToolbarButton(name: string | RegExp): Locator {
    return this.getMatrixToolbar().getByRole('button', { name, exact: typeof name === 'string' });
  }

  /** The "More actions" menu, opened. It lists what the toolbar has no room for. */
  async openMoreActions(): Promise<Locator> {
    const menu = this.page.getByRole('menu', { name: 'More actions' });
    if (!(await menu.isVisible())) await this.getToolbarButton('More actions').click();
    await expect(menu).toBeVisible();
    return menu;
  }

  /** Whether the action sits in the toolbar row; otherwise "More actions" lists it. */
  async isInToolbar(name: string): Promise<boolean> {
    // The toolbar renders its pinned parts first: wait for one so that the count below is not taken too early.
    await expect(this.getMatrixToolbar().getByRole('group', { name: 'Heatmap', exact: true })).toBeVisible();
    return (await this.getToolbarButton(name).count()) > 0;
  }

  getKillChainSelect(): Locator {
    return this.getMatrixToolbar().getByRole('combobox', { name: 'Kill chain' });
  }

  getKillChainOption(name: string): Locator {
    return this.page.getByRole('option', { name });
  }

  /**
   * The field sits in the toolbar when the row has room for it (a wide window); the specs that pick a platform
   * give the window that room, since a field in a submenu of "More actions" is not worth driving here.
   */
  getSecurityPostureSelect(): Locator {
    return this.getMatrixToolbar().getByRole('combobox', { name: 'Compare with my security posture' });
  }

  async selectSecurityPlatform(name: string) {
    await this.getSecurityPostureSelect().click();
    await this.getSecurityPostureSelect().fill(name);
    await this.page.getByRole('option', { name }).click();
  }

  // -- Heatmap

  getHeatmapToggle(): Locator {
    return this.getToolbarButton('Displays heat map of attack pattern use');
  }

  async toggleHeatmap() {
    await this.getHeatmapToggle().click();
  }

  /**
   * The legend of the toolbar, one image for assistive technologies: its name is "Technique usage scale, 1 to N".
   * The copy inside the matrix is hidden on screen and only drawn in the exported image and PDF.
   */
  getLegend(): Locator {
    return this.getMatrixToolbar().getByRole('img', { name: /^Technique usage scale, 1 to \d+$/ });
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

  // -- Matrix filters

  /** Opens the list of a filter (`Filter by type`, `Filter by marking`, `Filter by author`). The filters stay in the row in a wide window. */
  async openMatrixFilter(label: string): Promise<Locator> {
    await this.getToolbarButton(label).click();
    const menu = this.page.getByRole('menu', { name: label, exact: true });
    await expect(menu).toBeVisible();
    return menu;
  }

  /** Checks or unchecks a choice of the filter list that is open, then closes the list. */
  async toggleMatrixFilterOption(label: string) {
    await this.page.getByRole('menuitemcheckbox', { name: label }).click();
    await this.page.keyboard.press('Escape');
    await expect(this.page.getByRole('menu')).toHaveCount(0);
  }

  /** Writes the filters the matrix keeps for an investigation, as it does itself. Call on a page of the platform; reload for the matrix to read it. */
  async setStoredMatrixFilters(investigationId: string, filters: Partial<InvestigationMatrixFilters>) {
    await this.page.evaluate(
      ({ key, value }) => window.localStorage.setItem(key, value),
      // The key of `matrixFiltersStorageKey`, written out: importing it would load the graph parser in the test runner.
      { key: `investigation-matrix-filters-${investigationId}`, value: JSON.stringify(filters) },
    );
  }

  // -- Export: the image from the matrix toolbar, the PDF and STIX from the header

  getExportToImageButton(): Locator {
    return this.getToolbarButton('Export to image');
  }

  /** The image export of the header, which an investigation no longer has: its export moved to the toolbars. */
  getHeaderExportToImageButton(): Locator {
    return this.page.locator('#export-buttons').getByRole('button', { name: 'Export to image' });
  }

  getExportToPdfButton(): Locator {
    return this.page.locator('#export-buttons').getByRole('button', { name: 'Export to PDF' });
  }

  getDownloadStixButton(): Locator {
    return this.page.locator('#export-buttons').getByRole('button', { name: 'Download as STIX report' });
  }

  getExportPdfMenuItem(theme: 'Dark' | 'Light'): Locator {
    return this.page.getByRole('menuitem', { name: theme });
  }

  /**
   * Picks one image of the export list, from the toolbar or, when the row has no room for it (a narrow window),
   * from "More actions". The download starts once the item is picked: wait for it before calling.
   * The built-in themes are named `Filigran Light` and `Filigran Dark`: the item is matched on its end.
   */
  async exportImage(theme: 'Dark' | 'Light', background: 'with' | 'without' = 'with') {
    const name = new RegExp(`${theme} \\(${background} background\\)$`);
    if (await this.isInToolbar('Export to image')) {
      // Disabled while a previous export runs: wait for it to end.
      await expect(this.getExportToImageButton()).not.toHaveAttribute('aria-disabled', 'true');
      await this.getExportToImageButton().click();
      await this.page.getByRole('menu', { name: 'Export to image' }).getByRole('menuitem', { name }).click();
      return;
    }
    const moreActions = await this.openMoreActions();
    await moreActions.getByRole('menuitem', { name: /^Export to image/ }).click();
    await expect(this.page.getByRole('menu')).toHaveCount(2);
    // The pointer would travel from the submenu trigger to the item across the parent menu, which closes the
    // submenu on its way: the item is picked from the keyboard.
    const item = this.page.getByRole('menu').last().getByRole('menuitem', { name });
    await item.focus();
    await item.press('Enter');
  }
}
