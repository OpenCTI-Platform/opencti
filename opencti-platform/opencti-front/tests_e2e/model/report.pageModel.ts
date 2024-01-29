import { Page } from "@playwright/test";

export class ReportPage {
    constructor(private page: Page) {
    }

    getReportPage() {
        return this.page.getByTestId('report-page');
    }

    goToReportPage() {
        return this.page.getByLabel('Analyses').click();
    }

    addNewReport() {
        return this.page.getByLabel('Add', { exact: true }).click()
    }

    getReportNameInput() {
        return this.page.getByLabel('Name');
    }

    getCreateReportButton() {
        return this.page.getByRole('button', { name: 'Create' })
    }
}
