import { expect, Page } from '@playwright/test';
import LoginFormPageModel from './model/form/loginForm.pageModel';
import TopMenuProfilePage from './model/menu/topMenuProfile.pageModel';

// Must match the path used by auth.setup.ts.
const AUTH_FILE = 'tests_e2e/.setup/.auth/user.json';

/** Restores the shared admin session (storageState) after a setup spec logs out as another user, since all 'chromium'-project specs share one session cookie. */
export async function restoreAdminSession(page: Page) {
  const topBar = new TopMenuProfilePage(page);
  const loginForm = new LoginFormPageModel(page);

  await page.goto('/');
  await topBar.logout();
  await loginForm.login();
  // login() only waits for the URL to reach '/dashboard', but LoginForm.tsx's post-login
  // window.location.reload() can leave the app-shell still bootstrapping at that point - a
  // caller that immediately does its own page.goto() (e.g. draftsList.spec.ts) can race that
  // bootstrap and land back on the login page. Wait for the profile menu (used by
  // topBar.logout() as the "is authenticated" signal) to be stable before returning.
  await expect(topBar.getMenuProfile()).toBeVisible();
  await page.context().storageState({ path: AUTH_FILE });
}
