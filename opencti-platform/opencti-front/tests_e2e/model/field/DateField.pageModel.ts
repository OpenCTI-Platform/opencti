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
   * Types the input with key presses after selecting every section, as a user does, so that the
   * field's own keyboard editing stays covered (#19228). The field moves to the next section by
   * itself once one is full, and ignores the separators, but reads a space as a 0.
   */
  async type(input: string) {
    await this.fieldLocator.click();
    await this.page.keyboard.press('ControlOrMeta+A');
    await this.page.keyboard.type(input.replace(/\s+/g, ''), { delay: 100 });
  }

  /**
   * Enters each part of the input ("2023-12-05 12:00 AM": 2023, 12, 05, 12, 00, AM) in its own
   * section, in the order of the field's format, from an empty field.
   *
   * Typed keys are not reliable here. A full section moves to the next one only once the field
   * has rendered, so on a slow runner the next keys still reached it and it started over (a year
   * typed as "2023-12-05" ended as 0005). A field showing an error also keeps the keys typed
   * before it lost the focus, and the first keys typed in a section after that were lost (2023
   * became 0023). Each part is pasted instead: the field sets a selected section to a pasted value
   * in one event, and forgets the keys typed before.
   *
   * Clearing leaves every section selected, edited as one element with no section in it: a click
   * on the field gives them back. They are then targeted by their index, since a spinbutton role
   * is not always exposed.
   */
  async fill(input: string) {
    const parts = input.split(/[^0-9a-z]+/i).filter((part) => part.length > 0);
    await this.clear();
    await this.fieldLocator.click();
    for (const [index, part] of parts.entries()) {
      const section = this.fieldLocator.locator(
        `.MuiPickersSectionList-section[data-sectionindex="${index}"] .MuiPickersSectionList-sectionContent`,
      );
      await section.click();
      await section.evaluate((element, text) => {
        const clipboardData = new DataTransfer();
        clipboardData.setData('text', text);
        element.dispatchEvent(new ClipboardEvent('paste', { clipboardData, bubbles: true, cancelable: true }));
      }, part);
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
