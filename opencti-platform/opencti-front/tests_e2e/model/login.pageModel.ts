import { Page } from "@playwright/test";

export class LoginPage {
    constructor(private page: Page) {
    }

    getLogo() {
        return this.page.getByRole('heading', { name: 'by Filigran' })
    }

}