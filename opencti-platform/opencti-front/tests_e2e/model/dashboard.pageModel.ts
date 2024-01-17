import { Page } from "@playwright/test";

export class DashboardPage {
    constructor(private page: Page) {
    }
    getPage() {
        return this.page.getByTestId('dashboard-page');
    }
}
