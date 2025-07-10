import { expect, test } from './fixtures/baseFixtures';
import TopMenuProfilePage from './model/menu/topMenuProfile.pageModel';
import LoginFormPageModel from './model/form/loginForm.pageModel';

test('test logout', async ({ page }) => {
  const loginPage = new LoginFormPageModel(page);
  const topMenu = new TopMenuProfilePage(page);
  await page.goto('/');
  await topMenu.logout();
  await expect(loginPage.getPage()).toBeVisible();
});
