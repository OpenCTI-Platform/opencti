// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';

export default class DashboardPage {
    constructor(private page: Page) {
    }
    getPage() {
        return this.page.getByTestId('dashboard-page');
    }
    addNewDashboard() {
        return this.page.getByLabel('Add', { exact: true }).click()
    }
    getDashboardNameInput() {
        return this.page.getByLabel('Name');
    }
    addNewDashboardTag() {
        return this.page.getByLabel('Add tag', { exact: true }).click()
    }
    getCreateDashboardButton() {
        return this.page.getByRole('button', { name: 'Create' })
    }
    getItemFromList(name: string) {
        return this.page.getByRole('link', { name }).first()
    }
}
