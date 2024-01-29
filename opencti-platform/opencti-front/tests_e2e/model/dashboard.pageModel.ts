import { Page } from "@playwright/test";

export class DashboardPage {
    constructor(private page: Page) {
    }

    getDashboardPage() {
        return this.page.getByTestId('dashboard-page');
    }

    getDashboardButton() {
        return this.page.getByLabel('Dashboard', { exact: true })
    }

}
