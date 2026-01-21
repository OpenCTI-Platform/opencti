import { Page } from '@playwright/test';

export default class StixCoreObjectContentTabPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('sco-content-page');
  }

  async selectMainContent() {
    await this.page.getByRole('button', { name: 'Description & Main content' }).click();
    return this.getEditorViewButton().click();
  }

  async selectFile(name: string) {
    await this.page.getByText(name, { exact: true }).click();
    return this.page.getByLabel('Editing area: main');
  }

  async editMainContent(input: string) {
    await this.selectMainContent();
    return this.editTextArea(input, true);
  }

  async editTextArea(input: string, isAutoSave = false) {
    const element = this.page.getByTestId('text-area');
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

  async addTextFile(name: string) {
    await this.page.getByLabel('Add a file').click();
    const element = this.page.getByLabel('Name');
    await element.click();
    await element.fill(name);
    await this.page.getByRole('combobox', { name: 'Type HTML' }).click();
    await this.page.getByRole('option', { name: 'Text' }).click();
    return this.page.getByRole('button', { name: 'Create' }).click();
  }

  async addHtmlFile(name: string) {
    await this.page.getByLabel('Add a file').click();
    const element = this.page.getByLabel('Name');
    await element.click();
    await element.fill(name);
    return this.page.getByRole('button', { name: 'Create' }).click();
  }

  async editFile(name: string, input: string) {
    await this.page.getByRole('button', { name: name }).click();
    await this.page.getByText('Write something awesome...').click();
    return this.page.getByText('Write something awesome...').fill(input);
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
