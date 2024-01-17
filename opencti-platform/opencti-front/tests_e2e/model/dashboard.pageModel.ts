import { Page } from "@playwright/test";

export class DashboardPage {
    constructor(private page: Page) {
    }

    getDashboardButton() {
        return this.page.getByRole('link', { name: 'Dashboard', exact: true })
    }

}