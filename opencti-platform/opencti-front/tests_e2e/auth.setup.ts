import { expect, test as setup } from './fixtures/baseFixtures';
import { login } from "./common/login";
import { DashboardPage } from "./model/dashboard.pageModel";

const authFile = 'tests_e2e/.auth/user.json';

setup('authenticate', async ({ page }) => {
  await login(page);
  
  // End of authentication steps.
  
  await page.context().storageState({ path: authFile });
});
