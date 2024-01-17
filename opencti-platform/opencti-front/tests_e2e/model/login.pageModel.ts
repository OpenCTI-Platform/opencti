import { Page } from "@playwright/test";

export class LoginPage {
    constructor(private page: Page) {
    }

    getPage() {
        return this.page.getByTestId('login-page');
    }
    getLoginInput() {
        return this.page.getByLabel('Login')
    }
    async fillLoginInput(input: string) {
        await this.getLoginInput().click();
        return this.getLoginInput().fill(input);
    }
    async fillPasswordInput(input: string) {
        await this.getPasswordInput().click();
        return this.getPasswordInput().fill(input);
    }
    getPasswordInput() {
        return this.page.getByLabel('Password')
    }
    getSignInButton() {
        return this.page.getByRole('button', { name: 'Sign in' })
    }
}
