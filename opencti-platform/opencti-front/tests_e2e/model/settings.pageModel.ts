import { Page } from "@playwright/test";

export class SettingsPage {
    constructor(private page: Page) {
    }

    getSettingsPage() {
        return this.page.getByTestId('settings-page');
    }
}
