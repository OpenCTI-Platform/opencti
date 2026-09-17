import { Locator, Page, expect } from '@playwright/test';

export default class FiltersPageModel {
  private readonly root: Locator | Page;

  constructor(private page: Page, readonly rootLocator?: Locator) {
    this.root = rootLocator ?? page;
  }

  async addFilter(filterKey: string, filterLabel: string, addFilterLabel = 'Add filter') {
    await this.root.getByLabel(addFilterLabel).fill(filterKey);

    await expect(this.page.getByRole('option', { name: filterKey, exact: true })).toBeVisible();
    await this.page.getByRole('option', { name: filterKey, exact: true }).click();

    await expect(this.page.getByRole('combobox', { name: filterKey, exact: true })).toBeVisible();
    await this.page.getByRole('combobox', { name: filterKey }).click();

    await expect(this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox')).toBeVisible();
    await this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox').check();

    return this.page.mouse.click(10, 10);
  }

  async addFilterInDatatable(filterKey: string, filterLabel: string, deflakeButton: string) {
    await this.root.getByLabel('Add filter').fill(filterKey);

    await expect(this.page.getByRole('option', { name: filterKey })).toBeVisible();
    await this.page.getByRole('option', { name: filterKey }).click();

    const isLabelListVisible = await this.page.getByRole('combobox', { name: filterKey }).isVisible();
    if (!isLabelListVisible) {
      // This is probably a UI issue, that is random and I have no better idea so far.
      // Happens mostly when a graphQL request is done to fetch data
      // Since there is some cache the fetch is not always done
      await this.page.getByRole('button', { name: deflakeButton }).last().click();
    }
    await expect(this.page.getByRole('combobox', { name: filterKey })).toBeVisible();
    await this.page.getByRole('combobox', { name: filterKey }).click();

    await expect(this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox')).toBeVisible();
    await this.page.getByLabel(filterLabel, { exact: true }).getByRole('checkbox').check();

    return this.page.mouse.click(10, 10);
  }

  async addLabelFilter(labelValue: string) {
    const filterKey = 'Label';
    const deflakeButton = 'Label =';
    return this.addFilterInDatatable(filterKey, labelValue, deflakeButton);
  }

  async addEntityTypeFilter(filterLabel: string) {
    const filterKey = 'Entity type';
    const deflakeButton = 'Entity type =';
    return this.addFilterInDatatable(filterKey, filterLabel, deflakeButton);
  }

  // region Nested filter groups (issue #12062)
  // Selectors come from the real components:
  //  - ListFilters.tsx        -> the synthetic 'Add Filter Group' combobox option
  //  - FilterGroupChipButton  -> data-testid `filter-group-chip-<uuid>`
  //  - FilterGroupPanel.tsx   -> data-testid `filter-group-panel-<uuid>`,
  //                              `filter-group-mode-select-<uuid>`,
  //                              `filter-group-add-condition-<uuid>` (and its `-link-` variant)
  //  - FilterRow.tsx          -> data-testid `filter-row-key-select` / `filter-row-value`
  // The uuids are generated at runtime, hence the regex test ids.

  /** The [⛬ n rules ▾] button standing for the nested group in the filter line. */
  getGroupChip() {
    return this.root.getByTestId(/^filter-group-chip-/);
  }

  /** The recursive group editor, once opened from the chip. */
  getGroupPanel() {
    return this.root.getByTestId(/^filter-group-panel-/);
  }

  getGroupModeSelect() {
    return this.root.getByTestId(/^filter-group-mode-select-/);
  }

  /**
   * Adds an empty nested group at the ROOT level, through the synthetic option of the
   * filter key combobox.
   */
  async addFilterGroup(addFilterLabel = 'Add filter') {
    await this.root.getByLabel(addFilterLabel).click();

    const addGroupOption = this.page.getByRole('option', { name: 'Add Filter Group', exact: true });
    await expect(addGroupOption).toBeVisible();
    await addGroupOption.click();

    await expect(this.getGroupChip()).toBeVisible();
  }

  /** Opens the group edition panel by clicking its chip (the panel is never auto-opened). */
  async openGroupPanel() {
    await expect(this.getGroupChip()).toBeVisible();
    await this.getGroupChip().click();
    await expect(this.getGroupPanel()).toBeVisible();
  }

  /**
   * Switches the and/or mode OF THE GROUP (not of the root), through the design system
   * Select of the panel. `mode` is the displayed, uppercased value.
   */
  async switchGroupMode(mode: 'AND' | 'OR') {
    await this.getGroupModeSelect().click();
    const option = this.page.getByRole('option', { name: mode, exact: true });
    await expect(option).toBeVisible();
    await option.click();
    return this.expectGroupWithMode(mode);
  }

  /** The group panel is open and its mode select displays `mode`. */
  async expectGroupWithMode(mode: 'AND' | 'OR') {
    await expect(this.getGroupPanel()).toBeVisible();
    await expect(this.getGroupModeSelect()).toHaveText(mode);
  }

  /**
   * Adds one condition inside the opened group and gives it a value.
   * `filterKey` must be a basic text filter (e.g. 'Name'): its value editor is a plain
   * text field, validated by Enter, which keeps this step free of any server side search.
   */
  async addConditionInGroup(filterKey: string, value: string) {
    const panel = this.getGroupPanel();
    // `(?!link)` keeps the button apart from the `filter-group-add-condition-link-<uuid>`
    // shortcut rendered when the group is still empty.
    await panel.getByTestId(/^filter-group-add-condition-(?!link)/).click();

    await panel.getByTestId('filter-row-key-select').click();
    const keyOption = this.page.getByRole('option', { name: filterKey, exact: true });
    await expect(keyOption).toBeVisible();
    await keyOption.click();

    const valueInput = panel.getByTestId('filter-row-value').getByLabel(filterKey, { exact: true });
    await expect(valueInput).toBeVisible();
    await valueInput.fill(value);
    return valueInput.press('Enter');
  }

  /** The condition is present inside the group, with its value. */
  async expectConditionInGroup(filterKey: string, value: string) {
    const valueInput = this.getGroupPanel().getByTestId('filter-row-value').getByLabel(filterKey, { exact: true });
    await expect(valueInput).toBeVisible();
    await expect(valueInput).toHaveValue(value);
  }

  /**
   * The and/or separator displayed between two elements of the ROOT filter line
   * (lowercased label, see FilterIconButtonGlobalMode).
   */
  getRootModeSeparator(mode: 'and' | 'or') {
    return this.root.getByText(mode, { exact: true });
  }

  // endregion

  async removeLastFilter() {
    await expect(this.root.getByTestId('CancelIcon').last()).toBeVisible();
    await this.root.getByTestId('CancelIcon').last().click({ force: true });
  }
}
