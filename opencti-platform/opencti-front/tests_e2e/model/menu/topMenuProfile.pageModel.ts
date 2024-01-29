import { Page } from "@playwright/test";

export class TopMenuProfilePage {
    constructor(private page:Page) {
    }

    getMenuProfile() {
    return this.page.getByLabel('Profile');
    }
    getLogoutButton() {
        return this.page.getByRole('menuitem', { name: 'Logout' });
    }
}
