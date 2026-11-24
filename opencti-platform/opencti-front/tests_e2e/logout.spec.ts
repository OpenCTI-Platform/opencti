import { REGISTER_BANNER_DISMISSED_KEY } from '../src/utils/bannerConstants';
import { expect, test } from './fixtures/baseFixtures';
import TopMenuProfilePage from './model/menu/topMenuProfile.pageModel';
import LoginFormPageModel from './model/form/loginForm.pageModel';
import DashboardPage from './model/dashboard.pageModel';

// Log in with a session of its own: logging out of the shared session (tests_e2e/.setup/.auth)
// would log out every test that runs after this one, such as the scenarios of a CI shard.
test.use({ storageState: { cookies: [], origins: [] } });

test('test logout', { tag: ['@ce'] }, async ({ page }) => {
  const loginPage = new LoginFormPageModel(page);
  const topMenu = new TopMenuProfilePage(page);
  const dashboardPage = new DashboardPage(page);

  await page.addInitScript((key) => {
    localStorage.setItem(key, 'true');
  }, REGISTER_BANNER_DISMISSED_KEY);
  await page.goto('/');
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();

  await topMenu.logout();
  await expect(loginPage.getPage()).toBeVisible();

  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();
});
