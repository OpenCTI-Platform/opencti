import { Locator, Page } from '@playwright/test';

export default class AutocompleteFieldPageModel {
  private readonly inputLocator: Locator;
  private readonly parentLocator: Locator;

  constructor(
    private readonly page: Page,
    private readonly label: string,
    private readonly multiple: boolean,
    readonly rootLocator?: Locator,
  ) {
    this.inputLocator = (rootLocator ?? page).getByRole('combobox', { name: label });
    this.parentLocator = this.inputLocator.locator('../../../..');
  }

  async selectOption(option: string) {
    await this.inputLocator.click();
    await this.inputLocator.fill(option);
    const list = this.page.getByRole('listbox', { name: this.label });
    return list.getByText(option, { exact: true }).click();
  }

  getOption(option: string) {
    if (!this.multiple) return this.inputLocator;
    // Two DOM shapes live side by side while the migration runs. MUI renders a
    // selected value as a BUTTON named after it; the library renders it as a
    // list item inside a chip row named after the field. Matching either keeps
    // this model working for converted and unconverted sites alike.
    const muiChip = this.parentLocator.getByRole('button', { name: option });
    const libraryChip = (this.rootLocator ?? this.page)
      .getByRole('list', { name: this.label })
      .getByRole('listitem')
      .filter({ hasText: option });
    // .first() because on a converted field BOTH branches match the same chip:
    // the library gives its delete control an accessible name taken from the
    // label, so the MUI branch resolves it too. Two descriptions of one element,
    // not two elements — without this, strict mode fails on every chip.
    return muiChip.or(libraryChip).first();
  }

  /**
   * The persistent `+` beside the field, in the shape MUI's `AutocompleteField`
   * gives it. A converted field renders its own into the library's adornment
   * slot, which this locator does not reach — use `createOption` there.
   */
  openAddOptionForm() {
    return this.parentLocator.getByRole('button', { name: 'Add', exact: true }).click();
  }

  /**
   * The library create affordance: type a value the list does not hold, then
   * pick the `Create '<value>'` row, per design nodes 6920-11382 / 6920-11841.
   *
   * The row OPENS the creation form. Whether it PREFILLS it is per-site and must
   * be measured, not assumed — measured scoped to the dialog, since the page
   * behind it has inputs of the same name:
   *
   *   CreatedByField          -> passes `inputValue={keyword}` to IdentityCreation
   *                              -> dialog name = the typed text (PREFILLED)
   *   ExternalReferencesField -> passes no inputValue to ExternalReferenceCreation
   *                              -> source_name, external_id, url all EMPTY
   */
  async createOption(value: string) {
    await this.inputLocator.click();
    await this.inputLocator.fill(value);
    const list = this.page.getByRole('listbox', { name: this.label });
    // Matched by regex, not by a literal: the library's default wording comes
    // from the Figma node and uses TYPOGRAPHIC quotes — `Create ‘x’` — so a
    // test spelling it with apostrophes never resolves. The quote style is the
    // library's to change, and a product test must not be coupled to it.
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return list.getByText(new RegExp(`Create\\s*\\S?${escaped}`)).click();
  }

  getByText(input: string) {
    return this.parentLocator.getByText(input);
  }
}
