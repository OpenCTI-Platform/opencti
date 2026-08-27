import { Page } from '@playwright/test';
import LoginFormPageModel from './model/form/loginForm.pageModel';
import TopMenuProfilePage from './model/menu/topMenuProfile.pageModel';

// Must match the path used by auth.setup.ts.
const AUTH_FILE = 'tests_e2e/.setup/.auth/user.json';

/**
 * Every 'chromium'-project spec derives its browser context from the same storageState file
 * (same session cookie). Logging out destroys that session server-side (req.session.destroy in
 * httpPlatform.js), which would strand every other spec relying on that shared session on the
 * Login page. Call this at the end of any setup spec that logs out as a different user, to log
 * back in as admin and refresh the shared storageState file for downstream specs.
 */
export async function restoreAdminSession(page: Page) {
  const topBar = new TopMenuProfilePage(page);
  const loginForm = new LoginFormPageModel(page);

  await page.goto('/');
  await topBar.logout();
  await loginForm.login();
  await page.context().storageState({ path: AUTH_FILE });
}
