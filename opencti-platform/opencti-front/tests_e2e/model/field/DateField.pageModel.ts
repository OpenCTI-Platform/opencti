import { Locator, Page } from '@playwright/test';

export default class DateFieldPageModel {
  /**
   * The field is a group of editable sections, labelled by the field label. The
   * label also names a hidden <input> that only mirrors the value, so the group is
   * targeted by role rather than by label.
   */
  private readonly fieldLocator: Locator;

  constructor(
    private readonly page: Page,
    label: string,
    readonly rootLocator?: Locator,
  ) {
    this.fieldLocator = (rootLocator ?? page).getByRole('group', { name: label });
  }

  /** The hidden <input> mirroring the value: empty when the field is, disabled with it. */
  getInput() {
    return this.fieldLocator.locator('input');
  }

  /** The sections as displayed, with the format mask ("YYYY-MM-DD…") in the empty ones. */
  getSections() {
    return this.fieldLocator.locator('.MuiPickersSectionList-root');
  }

  value() {
    return this.getInput().inputValue();
  }

  async clear() {
    await this.fieldLocator.click();
    await this.page.keyboard.press('ControlOrMeta+A');
    return this.page.keyboard.press('Backspace');
  }

  /**
   * Types each part of the input ("2023-12-05 12:00 AM": 2023, 12, 05, 12, 00, AM) in its own
   * section, in the order of the field's format.
   *
   * A full section moves to the next one by itself, but only once the field has rendered: on a
   * slow runner the next keys still reach the full section, which starts over (a year typed as
   * "2023-12-05" ends as 0005). Clicking each section first does not depend on that timing.
   */
  async fill(input: string) {
    const parts = input.split(/[^0-9a-z]+/i).filter((part) => part.length > 0);
    const sections = this.fieldLocator.getByRole('spinbutton');
    for (const [index, part] of parts.entries()) {
      await sections.nth(index).click();
      await this.page.keyboard.type(part, { delay: 100 });
    }
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
    return this.fieldLocator
      .locator('xpath=ancestor::div[contains(@class,"MuiFormControl-root")][1]')
      .getByRole('button', { name: /Choose date/ });
  }

  /** The Clear button the adornment reveals once the field holds a value. */
  getClearButton() {
    return this.fieldLocator
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
    const popper = this.page.locator('.MuiPickerPopper-root');
    // Day cells are NOT `role=button` — MUI gives them `gridcell`, and their
    // accessible name is the full date ("14 December 2023"), not the number.
    // Matching the day class on its exact text is what actually selects one.
    await popper.locator('button.MuiPickerDay-root').filter({ hasText: new RegExp(`^${day}$`) }).click();
    await popper.getByRole('button', { name: 'OK' }).click();
  }
}
