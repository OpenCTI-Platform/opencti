import { Page } from "@playwright/test";

export class ArtifactPage {
    constructor(private page: Page) {
    }
    getPage() {
        return this.page.getByTestId('Artifact-page');
    }
    addNewArtifactImport() {
        return this.page.getByLabel('Add', { exact: true })
    }
}