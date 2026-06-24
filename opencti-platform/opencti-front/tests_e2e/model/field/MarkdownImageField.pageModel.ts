import path from 'path';
import { Locator, Page } from '@playwright/test';

export default class MarkdownImageFieldPageModel {
  private readonly editorLocator: Locator;

  constructor(
    readonly page: Page,
    label: string,
    rootLocator?: Locator,
  ) {
    const root = rootLocator ?? page;
    this.editorLocator = root.getByText(label).locator('../../../..');
  }

  /**
   * Upload an image via the hidden file input wired to the Insert Image button.
   * Playwright intercepts the file chooser so no native dialog appears.
   */
  async uploadImageViaButton(imagePath: string) {
    const fileChooserPromise = this.page.waitForEvent('filechooser');
    await this.editorLocator.getByTestId('markdown-image-upload-button').click();
    const fileChooser = await fileChooserPromise;
    await fileChooser.setFiles(path.resolve(imagePath));
  }

  /**
   * Upload an image by setting files directly on the hidden input.
   * More reliable when the button label is not stable.
   */
  async uploadImageViaInput(imagePath: string) {
    await this.editorLocator
      .locator('input[type="file"][accept]')
      .setInputFiles(path.resolve(imagePath));
  }

  /** Switch to the Preview tab of react-mde */
  async switchToPreview() {
    await this.editorLocator.getByRole('button', { name: 'Preview' }).click();
  }

  /** Switch back to the Write tab of react-mde */
  async switchToWrite() {
    await this.editorLocator.getByRole('button', { name: 'Write' }).click();
  }

  /**
   * Returns a locator for an img rendered inside the preview pane.
   * Useful for asserting that an image resolved properly.
   */
  getPreviewImage() {
    return this.editorLocator.locator('.mde-preview img');
  }

  /**
   * Returns a locator for the raw markdown textarea (Write mode).
   * Useful for asserting the temp token or final URL was inserted.
   */
  getTextarea() {
    return this.editorLocator.getByTestId('text-area');
  }
}
