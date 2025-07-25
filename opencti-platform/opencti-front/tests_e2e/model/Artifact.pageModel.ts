import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class ArtifactPage {
  constructor(private page: Page) {}

  getPage(name: string) {
    return this.page.getByTestId(name);
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Observations', 'Artifacts');
  }

  addNewArtifactImport() {
    return this.page.getByLabel('Create Artifact', { exact: true });
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name).first();
  }
}
