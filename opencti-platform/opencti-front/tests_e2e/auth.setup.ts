import { expect, test as setup } from './fixtures/baseFixtures';
import DashboardPage from './model/dashboard.pageModel';
import LoginFormPageModel from './model/form/loginForm.pageModel';

const authFile = 'tests_e2e/.setup/.auth/user.json';

// We need to always authenticate to allow retry on CI. Some test can fail with another user or while being logout.
setup('authenticate as admin(at)opencti.io by default', async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  const loginPage = new LoginFormPageModel(page);

  await page.goto('/');
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();
  // End of authentication steps.
  await page.context().storageState({ path: authFile });
});
