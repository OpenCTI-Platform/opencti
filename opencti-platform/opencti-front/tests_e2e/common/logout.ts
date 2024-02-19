import { LoginPage } from "../model/login.pageModel";
import { expect } from "../fixtures/baseFixtures";
import { TopMenuProfilePage } from "../model/menu/topMenuProfile.pageModel";

export async function logout(page) {
    const loginPage = new LoginPage(page);
    const menuProfile = new TopMenuProfilePage(page);
    await menuProfile.getMenuProfile().click();
    await menuProfile.getLogoutButton().click();
    await expect(loginPage.getPage()).toBeVisible();
}
