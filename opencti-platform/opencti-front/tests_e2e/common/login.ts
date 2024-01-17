import { LoginPage } from "../model/login.pageModel";
import { expect } from "../fixtures/baseFixtures";
import { DashboardPage } from "../model/dashboard.pageModel";

export async function login(page) {
    const loginPage = new LoginPage(page);
    const dashboardPage = new DashboardPage(page);
    await page.goto('/');
    await expect(loginPage.getPage()).toBeVisible();
    await loginPage.fillLoginInput('admin@opencti.io');
    await loginPage.fillPasswordInput('admin');
    await loginPage.getSignInButton().click();
    await expect(dashboardPage.getPage()).toBeVisible();
}
