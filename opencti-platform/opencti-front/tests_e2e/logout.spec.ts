import { test } from "./fixtures/baseFixtures";
import { logout } from "./common/logout";

test.use({ storageState: 'tests_e2e/.setup/.auth/logout-user.json' });
test('test logout', async ({ page }) => {
  await page.goto('/');
  await logout(page);
});
