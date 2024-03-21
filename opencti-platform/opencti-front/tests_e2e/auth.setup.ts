import { expect, test as setup } from './fixtures/baseFixtures';
import DashboardPage from './model/dashboard.pageModel';
import LoginPage from './model/login.pageModel';
import * as fs from 'fs';

const authFile = 'tests_e2e/.setup/.auth/user.json';
const prepLogoutFile = 'tests_e2e/.setup/.auth/logout-user.json';

// For quicker local testing, don't redo the auth if the seed is still valid
const authSessionStorage = JSON.parse(fs.readFileSync(authFile, 'utf-8'));
const logoutSessionStorage = JSON.parse(fs.readFileSync(prepLogoutFile, 'utf-8'));

setup('authenticate', async ({ page }) => {
  if (authSessionStorage.cookies[0].expires > (Date.now() / 1000)) {
    return;
  }
  const dashboardPage = new DashboardPage(page);
  const loginPage = new LoginPage(page);
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();
  // End of authentication steps.
  await page.context().storageState({ path: authFile });
});

setup('authenticate for logout user', async ({ page }) => {
  if (logoutSessionStorage.cookies[0].expires > (Date.now() / 1000)) {
    return;
  }
  const dashboardPage = new DashboardPage(page);
  const loginPage = new LoginPage(page);
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();
  // End of authentication steps.
  await page.context().storageState({ path: prepLogoutFile });
});
