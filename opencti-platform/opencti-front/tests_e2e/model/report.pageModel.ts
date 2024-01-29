import { Page } from "@playwright/test";

export class ReportPage {
    constructor(private page: Page) {
    }

    getReportPage() {
        return this.page.getByTestId('report-page');
    }
}
