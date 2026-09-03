import { expect, Locator, Page } from '@playwright/test';

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
    const target = list.getByText(option, { exact: true });
    try {
      await target.waitFor({ state: 'visible', timeout: 15000 });
    } catch {
      // Options are refreshed by a single fire-and-forget search per input change, so a response
      // that came back without the option (data not indexed yet) is never re-issued on its own.
      await expect(async () => {
        await this.inputLocator.fill('');
        await this.inputLocator.fill(option);
        await expect(target).toBeVisible({ timeout: 5000 });
      }).toPass({ timeout: 60000, intervals: [1000] });
    }
    return target.click();
  }

  getOption(option: string) {
    return this.multiple
      ? this.parentLocator.getByRole('button', { name: option })
      : this.inputLocator;
  }

  openAddOptionForm() {
    return this.parentLocator.getByRole('button', { name: 'Add', exact: true }).click();
  }

  getByText(input: string) {
    return this.parentLocator.getByText(input);
  }
}
