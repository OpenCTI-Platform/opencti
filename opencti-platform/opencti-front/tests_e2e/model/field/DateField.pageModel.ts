import { Locator, Page } from '@playwright/test';

export default class DateFieldPageModel {
  private readonly inputLocator: Locator;

  constructor(
    private readonly page: Page,
    label: string,
    readonly rootLocator?: Locator,
  ) {
    this.inputLocator = (rootLocator ?? page).getByLabel(label);
  }

  getInput() {
    return this.inputLocator;
  }

  value() {
    return this.inputLocator.inputValue();
  }

  async clear() {
    await this.inputLocator.click();
    await this.page.keyboard.press('ControlOrMeta+A');
    return this.page.keyboard.press('Backspace');
  }

  async fill(input: string) {
    await this.inputLocator.click();
    return this.page.keyboard.type(input, { delay: 100 });
  }

  /**
   * The calendar trigger inside the field's own adornment.
   *
   * Scoped to the field's FormControl rather than to the page: a form can hold
   * more than one date field, and every one of them names this button the same
   * way. The accessible name gains a ", selected date is …" suffix once the
   * field holds a value, so it is matched by prefix.
   */
  getPickerButton() {
    return this.inputLocator
      .locator('xpath=ancestor::div[contains(@class,"MuiFormControl-root")][1]')
      .getByRole('button', { name: /Choose date/ });
  }

  /** The Clear button the adornment reveals once the field holds a value. */
  getClearButton() {
    return this.inputLocator
      .locator('xpath=ancestor::div[contains(@class,"MuiFormControl-root")][1]')
      .getByRole('button', { name: 'Clear' });
  }

  /**
   * Opens the calendar, picks a day of the displayed month and accepts it.
   * No waits: every step is an auto-waiting locator action.
   */
  async pickDay(day: string) {
    await this.getPickerButton().click();
    // Scoped to the popper: a bare day number would otherwise match anything
    // else on the page that happens to be labelled with the same digits.
    const popper = this.page.locator('.MuiPickersPopper-root');
    await popper.getByRole('button', { name: day, exact: true }).click();
    await popper.getByRole('button', { name: 'OK' }).click();
  }
}
