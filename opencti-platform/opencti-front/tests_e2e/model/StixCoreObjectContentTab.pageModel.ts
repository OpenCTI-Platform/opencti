import { Page } from '@playwright/test';

export default class StixCoreObjectContentTabPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('sco-content-page');
  }

  // The design-system RichTextField's editing area is a textbox named after
  // its label: "Content" for the main content field and for HTML files alike.
  getEditor() {
    return this.page.getByRole('textbox', { name: 'Content', exact: true });
  }

  async selectMainContent() {
    await this.page.getByRole('button', { name: 'Description & Main content' }).click();
    await this.getEditorViewButton().click();
    return this.getEditor();
  }

  async selectFile(name: string) {
    await this.page.getByText(name, { exact: true }).click();
    return this.getEditor();
  }

  async editMainContent(input: string) {
    await this.selectMainContent();
    return this.editTextArea(input, true);
  }

  async editTextArea(input: string, isAutoSave = false) {
    const element = this.getEditor();
    await element.click();
    if (isAutoSave) {
      await element.fill(input);
      // We wait for changes to be saved before leaving page
      return new Promise((r) => {
        setTimeout(r, 4000);
      });
    }

    await element.fill(input);
    return this.page.getByLabel('Save').click();
  }

  // only in HTML (default) for now
  async addFile(name: string) {
    await this.page.getByLabel('Add a file').click();
    const element = this.page.getByLabel('Name');
    await element.click();
    await element.fill(name);
    return this.page.getByRole('button', { name: 'Create' }).click();
  }

  async editFile(name: string, input: string) {
    await this.page.getByText(name).click();
    return this.editTextArea(input);
  }

  getContentMappingViewButton() {
    return this.page.getByLabel('Content mapping view');
  }

  getContentViewButton() {
    return this.page.getByLabel('Content view');
  }

  getEditorViewButton() {
    return this.page.getByLabel('Editor view');
  }
}
