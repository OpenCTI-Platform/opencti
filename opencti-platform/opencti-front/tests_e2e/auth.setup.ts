import { expect, test as setup } from './fixtures/baseFixtures';
import DashboardPage from './model/dashboard.pageModel';
import LoginPage from './model/login.pageModel';

const authFile = 'tests_e2e/.setup/.auth/user.json';
const prepLogoutFile = 'tests_e2e/.setup/.auth/logout-user.json';

setup('authenticate', async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  const loginPage = new LoginPage(page);
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();
  // End of authentication steps.
  await page.context().storageState({ path: authFile });
});

setup('authenticate for logout user', async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  const loginPage = new LoginPage(page);
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();
  // End of authentication steps.
  await page.context().storageState({ path: prepLogoutFile });
});
