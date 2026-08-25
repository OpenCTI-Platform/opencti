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
    return this.multiple
      ? this.parentLocator.getByRole('button', { name: option })
      : this.inputLocator;
  }

  /**
   * The MUI-era create affordance: a persistent `+` overlaid on the field.
   * Still used by every site that has not been converted to the library
   * Combobox — `CreatedByField`, `ExternalReferencesField` and the rest.
   */
  openAddOptionForm() {
    return this.parentLocator.getByRole('button', { name: 'Add', exact: true }).click();
  }

  /**
   * The library create affordance: type a value the list does not hold, then
   * pick the `Create '<value>'` row. Per design nodes 6920-11382 / 6920-11841,
   * accepted 2026-08-25 — the persistent `+` is gone on converted sites, so the
   * creation form opens carrying the typed text instead of empty.
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
