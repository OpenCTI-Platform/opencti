import { LoginPage } from "../model/login.pageModel";
import { DashboardPage } from "../model/dashboard.pageModel";
import { expect } from "@playwright/test";

export async function logout(page) {
    const loginPage = new LoginPage(page);
    await page.getByLabel('Profile').click();
    await page.getByRole('menuitem', { name: 'Logout' }).click();
    await expect(loginPage.getLogo()).toBeVisible();
}
