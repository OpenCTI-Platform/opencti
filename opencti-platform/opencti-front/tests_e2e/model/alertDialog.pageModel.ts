import { Page } from "@playwright/test";

export class AlertDialog {
    constructor(private page: Page) {
    }

    getOpenSettingsButton() {
        return this.page.getByRole('button', { name: 'Open Settings' })
    }
}
