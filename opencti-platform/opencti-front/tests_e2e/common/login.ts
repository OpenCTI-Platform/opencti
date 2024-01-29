import { LoginPage } from "../model/login.pageModel";
import { DashboardPage } from "../model/dashboard.pageModel";
import { expect } from "@playwright/test";
import { AlertDialog } from "../model/alertDialog.pageModel";
import { SettingsPage } from "../model/settings.pageModel";

export async function login(page) {
    const loginPage = new LoginPage(page);
    const dashboardPage = new DashboardPage(page);
    const alertDialog = new AlertDialog(page);
    const settingsPage = new SettingsPage(page);
    await page.goto('http://localhost:3000/');
    await expect(loginPage.getLoginPage()).toBeVisible();
    await loginPage.getLoginInput().click();
    await loginPage.getLoginInput().fill('admin@opencti.io');
    await loginPage.getPasswordInput().click();
    await loginPage.getPasswordInput().fill('admin');
    await loginPage.getSignInButton().click();
    await alertDialog.getOpenSettingsButton().click();
    await expect(settingsPage.getSettingsPage()).toBeVisible();
    await dashboardPage.getDashboardButton().click();
    await expect(dashboardPage.getDashboardPage()).toBeVisible();
}
