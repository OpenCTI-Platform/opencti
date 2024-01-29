
import { Page } from "@playwright/test";

export class ReportDetailsPage {
    constructor(private page: Page) {
    }

    getReportDetailsPage() {
        return this.page.getByTestId('report-details-page');
    }
}
