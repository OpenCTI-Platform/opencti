import { Page } from "@playwright/test";

export class ArtifactImportPage {
    constructor(private page: Page) {
    }
    getFileInput() {
        return this.page.getByLabel('file');
    }
    async fillFileInput(input: string) {
        await this.getFileInput().click();
        return this.getFileInput().fill(input);
    }
    getCreateArtifactImportButton() {
        return this.page.getByRole('button', { name: 'Create' });
    }
    getErrorMessage() {
        return this.page.getByText('This field is required')
    }
};