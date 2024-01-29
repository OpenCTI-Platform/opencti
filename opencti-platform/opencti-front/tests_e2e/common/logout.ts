import { LoginPage } from "../model/login.pageModel";
import { DashboardPage } from "../model/dashboard.pageModel";
import { expect } from "@playwright/test";
import { TopMenuProfilePage } from "../model/menu/topMenuProfile.pageModel";

export async function logout(page) {
    const loginPage = new LoginPage(page);
    const menuProfile = new TopMenuProfilePage(page);
    await menuProfile.getMenuProfile().click();
    await menuProfile.getLogoutButton().click();
    await expect(loginPage.getLoginPage()).toBeVisible();
}
