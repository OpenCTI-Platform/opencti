import { Page } from "@playwright/test";

export class ArtifactImportPage {
    constructor(private page: Page) {
    }
    getFileInput() {
        return this.page.getByLabel('file');
    }
    getCreateArtifactImportButton() {
        return this.page.getByRole('button', { name: 'Create' });
    }
    getErrorMessage() {
        return this.page.getByText('This field is required')
    }
};