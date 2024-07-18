import { Page } from '@playwright/test';

export default class ArtifactPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('Artifact-page');
  }

  addNewArtifactImport() {
    return this.page.getByLabel('Create Artifact', { exact: true });
  }
}
