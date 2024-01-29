import { Page } from "@playwright/test";

export class DashboardPage {
    constructor(private page: Page) {
    }

    getDashboardPage() {
        return this.page.getByTestId('dashboard-page');
    }

    getDashboardButton() {
        return this.page.getByRole('link', { name: 'Dashboard', exact: true })
    }

}
