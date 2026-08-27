import { Locator, Page } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';

/**
 * Wraps the "Import data" dialog's "Import using a Form" mode (`ImportFilesDialog.tsx` ->
 * `ImportFilesFormSelector.tsx` -> `ImportFilesFormView.tsx`), which embeds the same `FormView.tsx`
 * as the standalone form route, so `FormIntakeFillPageModel` is reused for filling/submitting.
 */
export default class ImportFilesDialogPageModel {
  private readonly dialog: Locator;

  constructor(private readonly page: Page) {
    this.dialog = page.getByRole('dialog');
  }

  /** Scopes locators to this dialog so they don't match same-named elements behind it. */
  getRoot() {
    return this.dialog;
  }

  async open() {
    await this.page.getByRole('button', { name: 'Import data' }).click();
    await expect(this.dialog).toBeVisible();
  }

  async selectFormMode() {
    await this.dialog.getByRole('button', { name: 'Import using a Form' }).click();
  }

  /** Selects a form from the list by its (unique) name - the button's accessible name also
   * includes the form's description, so non-exact matching is used. */
  async selectForm(name: string) {
    await this.dialog.getByRole('button', { name }).click();
  }
}
