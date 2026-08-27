import { Locator, Page } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';

/**
 * Wraps the "Import data" dialog opened from the top bar's upload icon (`UploadImport.tsx` ->
 * `ImportFilesDialog.tsx`), specifically its "Import using a Form" mode
 * (`ImportFilesToggleMode.tsx` -> `ImportFilesFormSelector.tsx` -> `ImportFilesFormView.tsx`).
 * `ImportFilesFormView` embeds the same `FormView.tsx` used by the standalone
 * `/dashboard/integrations/feeds/form/:formId` route, so `FormIntakeFillPageModel` is reused
 * as-is for filling/submitting once a form is selected.
 */
export default class ImportFilesDialogPageModel {
  private readonly dialog: Locator;

  constructor(private readonly page: Page) {
    this.dialog = page.getByRole('dialog');
  }

  /** Scopes locators to this dialog - pass to `FormIntakeFillPageModel` so it doesn't also
   * match same-named elements from the underlying page behind the dialog. */
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
