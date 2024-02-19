import { expect, test } from "./fixtures/baseFixtures";
import { LoginPage } from "./model/login.pageModel";
import { TopMenuProfilePage } from "./model/menu/topMenuProfile.pageModel";

test.use({ storageState: 'tests_e2e/.setup/.auth/logout-user.json' });
test('test logout', async ({ page }) => {
  const loginPage = new LoginPage(page);
  const topMenu = new TopMenuProfilePage(page)
  await page.goto('/');
  await topMenu.logout();
  await expect(loginPage.getPage()).toBeVisible();
});
