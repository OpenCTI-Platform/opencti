import { Page } from '@playwright/test';

export default class StixDomainObjectContentTabPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('sdo-content-page');
  }

  async selectMainContent() {
    await this.page.getByRole('button', { name: 'Main content Embedded content' }).click();
    return this.page.getByLabel('Editor editing area: main');
  }

  async selectFile(name: string) {
    await this.page.getByText(name, { exact: true }).click();
    return this.page.getByLabel('Editor editing area: main');
  }

  async editMainContent(input: string) {
    await this.selectMainContent();
    return this.editTextArea(input);
  }

  async editTextArea(input: string) {
    const element = this.page.getByLabel('Editor editing area: main');
    await element.click();
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
}
