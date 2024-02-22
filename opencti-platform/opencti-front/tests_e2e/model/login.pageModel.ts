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
    
    async login() {
        await this.page.goto('/');
        await this.page.waitForTimeout(5000);
        const buffer = await this.page.screenshot();
        console.log(buffer.toString('base64'));
        await this.fillLoginInput('admin@opencti.io');
        await this.fillPasswordInput('admin');
        return this.getSignInButton().click();
    }
}
