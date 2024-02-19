import { test as setup } from './fixtures/baseFixtures';
import { login } from "./common/login";

const authFile = 'tests_e2e/.setup/.auth/user.json';
const prepLogoutFile = 'tests_e2e/.setup/.auth/logout-user.json';

setup('authenticate', async ({ page }) => {
  await login(page);
  // End of authentication steps.
  await page.context().storageState({ path: authFile });
});

setup('authenticate for logout user', async ({ page }) => {
  await login(page);
  // End of authentication steps.
  await page.context().storageState({ path: prepLogoutFile });
});
