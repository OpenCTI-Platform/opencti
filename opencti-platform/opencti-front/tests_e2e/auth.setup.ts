import { expect, test as setup } from './fixtures/baseFixtures';
import DashboardPage from './model/dashboard.pageModel';
import LoginFormPageModel from './model/form/loginForm.pageModel';
import { REGISTER_BANNER_DISMISSED_KEY } from '../src/utils/bannerConstants';

const authFile = 'tests_e2e/.setup/.auth/user.json';

// We need to always authenticate to allow retry on CI. Some test can fail with another user or while being logout.
setup('authenticate as admin(at)opencti.io by default', async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  const loginPage = new LoginFormPageModel(page);

  await page.goto('/');
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();

  // Dismiss the RegisterPlatformBanner so its fixed-position button does not intercept clicks in any test
  await page.evaluate((key) => {
    localStorage.setItem(key, 'true');
  }, REGISTER_BANNER_DISMISSED_KEY);

  // End of authentication steps.
  await page.context().storageState({ path: authFile });
});
