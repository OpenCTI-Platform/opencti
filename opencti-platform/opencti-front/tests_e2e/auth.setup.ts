import * as fs from 'fs';
import { expect, test as setup } from './fixtures/baseFixtures';
import DashboardPage from './model/dashboard.pageModel';
import LoginFormPageModel from './model/form/loginForm.pageModel';

const authFile = 'tests_e2e/.setup/.auth/user.json';
const prepLogoutFile = 'tests_e2e/.setup/.auth/logout-user.json';

let authSessionStorage: { cookies: { expires: number }[] };
let logoutSessionStorage: { cookies: { expires: number }[] };
try {
// For quicker local testing, don't redo the auth if the seed is still valid
  authSessionStorage = JSON.parse(fs.readFileSync(authFile, 'utf-8'));
  logoutSessionStorage = JSON.parse(fs.readFileSync(prepLogoutFile, 'utf-8'));
} catch (e) {
  // eslint-disable-next-line no-console
  console.log('Initialing auth setup');
}

setup('authenticate', async ({ page }) => {
  if ((authSessionStorage?.cookies?.[0]?.expires ?? 0) > (Date.now() / 1000)) {
    return;
  }
  const dashboardPage = new DashboardPage(page);
  const loginPage = new LoginFormPageModel(page);

  await page.goto('/');
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();
  // End of authentication steps.
  await page.context().storageState({ path: authFile });
});

setup('authenticate for logout user', async ({ page }) => {
  if ((logoutSessionStorage?.cookies?.[0]?.expires ?? 0) > (Date.now() / 1000)) {
    return;
  }
  const dashboardPage = new DashboardPage(page);
  const loginPage = new LoginFormPageModel(page);

  await page.goto('/');
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();
  // End of authentication steps.
  await page.context().storageState({ path: prepLogoutFile });
});
