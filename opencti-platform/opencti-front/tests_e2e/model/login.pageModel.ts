import { Page } from "@playwright/test";

export class LoginPage {
    constructor(private page: Page) {
    }

    getLoginPage() {
        return this.page.getByTestId('login-page');
    }
    getLoginInput() {
        return this.page.getByLabel('Login')
    }
    getPasswordInput() {
        return this.page.getByLabel('Password')
    }
    getSignInButton() {
        return this.page.getByRole('button', { name: 'Sign in' })
    }
}
