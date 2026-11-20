import { expect, Locator, Page } from '@playwright/test';

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

  // -- Matrix toolbar: docked under the matrix, it holds what the matrix view does (kill chain, display, heatmap, posture, export)

  getMatrixToolbar(): Locator {
    return this.page.getByRole('toolbar', { name: 'Matrix toolbar' });
  }

  /** A button of the matrix toolbar; other buttons of the page (the header's) may carry the same name. */
  getToolbarButton(name: string | RegExp): Locator {
    return this.getMatrixToolbar().getByRole('button', { name, exact: typeof name === 'string' });
  }

  /** A part of the toolbar named for assistive technologies: `Display`, `Heatmap`. */
  getToolbarGroup(name: string): Locator {
    return this.getMatrixToolbar().getByRole('group', { name, exact: true });
  }

  /** The "More actions" menu, opened. It lists what the toolbar has no room for. */
  async openMoreActions(): Promise<Locator> {
    const menu = this.page.getByRole('menu', { name: 'More actions' });
    if (!(await menu.isVisible())) await this.getToolbarButton('More actions').click();
    await expect(menu).toBeVisible();
    return menu;
  }

  /** Whether the action sits in the toolbar row; otherwise "More actions" lists it (or the matrix does not offer it). */
  async isInToolbar(name: string): Promise<boolean> {
    // The toolbar renders its pinned parts first: wait for one so that the count below is not taken too early.
    await expect(this.getToolbarGroup('Heatmap')).toBeVisible();
    return (await this.getToolbarButton(name).count()) > 0;
  }

  getKillChainSelect(): Locator {
    return this.getMatrixToolbar().getByRole('combobox', { name: 'Kill chain' });
  }

  getKillChainOption(name: string): Locator {
    return this.page.getByRole('option', { name });
  }

  getOnlyUsedToggle(): Locator {
    return this.getToolbarButton(/^Display (only used techniques|the whole matrix)$/);
  }

  getSecurityPostureSelect(): Locator {
    return this.getMatrixToolbar().getByRole('combobox', { name: 'Compare with my security posture' });
  }

  /**
   * The field sits in the toolbar when the row has room for it (a wide window); the specs that pick a platform
   * give the window that room, since a field in a submenu of "More actions" is not worth driving here.
   */
  async selectSecurityPlatform(name: string) {
    await this.getSecurityPostureSelect().click();
    await this.getSecurityPostureSelect().fill(name);
    await this.page.getByRole('option', { name }).click();
  }

  // -- Heatmap

  getHeatmapToggle(): Locator {
    // Disabled, the toolbar draws a focusable wrapper named the same: hovering it opens the tooltip that says why.
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

  /** The copy of the legend inside the matrix: `hidden` on screen, shown for the capture of the image and the PDF. */
  getExportOnlyLegend(): Locator {
    return this.getMatrix().locator('[data-matrix-export-only]');
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

  /**
   * Picks one image of the export list, from the toolbar or, when the row has no room for it (a narrow window),
   * from "More actions". The download starts once the item is picked: wait for it before calling.
   */
  async exportImage(theme: 'Dark' | 'Light', background: 'with' | 'without' = 'with') {
    const name = `${theme} (${background} background)`;
    if (await this.isInToolbar('Export to image')) {
      await this.getExportToImageButton().click();
      await this.page.getByRole('menu', { name: 'Export to image' }).getByRole('menuitem', { name, exact: true }).click();
      return;
    }
    const moreActions = await this.openMoreActions();
    await moreActions.getByRole('menuitem', { name: /^Export to image/ }).click();
    await expect(this.page.getByRole('menu')).toHaveCount(2);
    // The pointer would travel from the submenu trigger to the item across the parent menu, which closes the
    // submenu on its way: the item is picked from the keyboard.
    const item = this.page.getByRole('menu').last().getByRole('menuitem', { name, exact: true });
    await item.focus();
    await item.press('Enter');
  }

  getExportPdfMenuItem(theme: 'Dark' | 'Light'): Locator {
    return this.page.getByRole('menuitem', { name: theme });
  }

  /** What the matrix leaves out of the selected kill chain: `N attack patterns not shown`. */
  getUnplacedNote() {
    return this.getMatrixToolbar().getByText(/^\d+ attack patterns? not shown$/);
  }

  getEmptyMatrixText() {
    return this.getMatrix().getByText('Add attack patterns to the graph view to visualise them here');
  }
}
