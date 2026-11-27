import type { APIRequestContext, Browser, Page, TestInfo } from '@playwright/test';
import { expect, prefixUrl, test } from '../fixtures/baseFixtures';
import LoginFormPageModel from '../model/form/loginForm.pageModel';
import SelectFieldPageModel from '../model/field/SelectField.pageModel';
import UserPage from '../model/user.pageModel';

const LOCKED_USER = {
  name: 'TestLocalAuthLockout',
  email: 'test-local-auth-lockout@filigran.test',
  password: 'LockoutPassword1!',
};
const WRONG_PASSWORD = 'WrongPassword1!';
// Both thresholds get this value, so that the test does not depend on the groups the platform gives to a new user
const MAX_ATTEMPTS = 3;

const BAD_LOGIN_MESSAGE = 'Bad login or password';
const TEMPORARY_LOCK_MESSAGE = /Your account has been locked for security reasons\. Please try again in \d+ minutes?\./;
const PERMANENT_LOCK_MESSAGE = 'Your account has been locked for security reasons. Please contact your administrator.';

type LockoutPolicy = {
  local_auth_lockout_enabled: boolean;
  local_auth_lockout_max_attempts: number;
  local_auth_lockout_admin_max_attempts: number;
  local_auth_lockout_final_action: 'temporary' | 'permanent';
  local_auth_lockout_window: number;
  local_auth_lockout_duration: number;
};

/**
 * Runs a GraphQL document as the admin (stored session), failing on any error.
 */
const graphql = async <T>(request: APIRequestContext, query: string, variables: Record<string, unknown> = {}): Promise<T> => {
  const response = await request.post('/graphql', { data: { query, variables } });
  const body = await response.json();
  if (body.errors?.length || !body.data) {
    throw new Error(`GraphQL request failed: ${JSON.stringify(body.errors ?? body)}`);
  }
  return body.data;
};

const readLockoutPolicy = async (request: APIRequestContext) => {
  const { settings } = await graphql<{ settings: LockoutPolicy & { id: string; local_auth: { enabled: boolean } } }>(request, `
    query {
      settings {
        id
        local_auth { enabled }
        local_auth_lockout_enabled
        local_auth_lockout_max_attempts
        local_auth_lockout_admin_max_attempts
        local_auth_lockout_final_action
        local_auth_lockout_window
        local_auth_lockout_duration
      }
    }
  `);
  const { id, local_auth, ...policy } = settings;
  return { id, localAuthEnabled: local_auth.enabled, policy };
};

// The local authentication is enabled while the tests log in with a password, and set back to its previous value at the end
const updateLockoutPolicy = async (request: APIRequestContext, settingsId: string, policy: LockoutPolicy, localAuthEnabled = true) => {
  await graphql(request, `
    mutation ($id: ID!, $input: LocalAuthConfigInput!) {
      settingsEdit(id: $id) {
        updateLocalAuth(input: $input) { id }
      }
    }
  `, { id: settingsId, input: { enabled: localAuthEnabled, ...policy } });
};

const ensureLockedUser = async (request: APIRequestContext) => {
  const { users } = await graphql<{ users: { edges: { node: { id: string; user_email: string } }[] } }>(request, `
    query ($search: String) {
      users(search: $search) { edges { node { id user_email } } }
    }
  `, { search: LOCKED_USER.email });
  const existing = users.edges.find(({ node }) => node.user_email === LOCKED_USER.email);
  if (existing) {
    return existing.node.id;
  }
  const { userAdd } = await graphql<{ userAdd: { id: string } }>(request, `
    mutation ($input: UserAddInput!) {
      userAdd(input: $input) { id }
    }
  `, { input: { name: LOCKED_USER.name, user_email: LOCKED_USER.email, password: LOCKED_USER.password } });
  return userAdd.id;
};

const readAccountStatus = async (request: APIRequestContext, userId: string) => {
  const { user } = await graphql<{ user: { account_status: string } }>(request, `
    query ($id: String!) {
      user(id: $id) { account_status }
    }
  `, { id: userId });
  return user.account_status;
};

// Setting the account back to Active also resets its failed attempts and its lock
const setAccountActive = async (request: APIRequestContext, userId: string) => {
  await graphql(request, `
    mutation ($id: ID!) {
      userEdit(id: $id) {
        fieldPatch(input: [{ key: "account_status", value: ["Active"] }]) { id }
      }
    }
  `, { id: userId });
};

/**
 * Opens the login page in a fresh browser context: the attempts of the locked user never touch the admin session of `page`.
 */
const openLoginPage = async (browser: Browser, testInfo: TestInfo) => {
  const { baseURL, viewport, ignoreHTTPSErrors } = testInfo.project.use;
  const context = await browser.newContext({ baseURL, viewport, ignoreHTTPSErrors, storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();
  await page.goto(prefixUrl('/'));
  const loginForm = new LoginFormPageModel(page);
  await expect(loginForm.getPage()).toBeVisible();
  return { context, page, loginForm };
};

// The token mutation of the login form accepts one call per second for the whole platform: a faster attempt is rejected
// with "Too many requests" before the lockout counts it. Every login of this spec waits a bit more than that first
const waitForLoginRateLimit = (page: Page) => page.waitForTimeout(1500);

/**
 * Submits the login form once, and waits for the message shown under the login field.
 */
const attemptLogin = async (page: Page, loginForm: LoginFormPageModel, password: string, message: string | RegExp) => {
  await waitForLoginRateLimit(page);
  await loginForm.nameField.fill(LOCKED_USER.email);
  await loginForm.passwordField.fill(password);
  await loginForm.getSignInButton().click();
  await expect(page.getByText(message)).toBeVisible();
};

test.describe('Local authentication lockout', { tag: ['@ce'] }, () => {
  test.describe.configure({ mode: 'serial' });

  let settingsId: string;
  let previousPolicy: LockoutPolicy;
  let previousLocalAuthEnabled: boolean;
  let userId: string;

  test.beforeAll(async ({ request }) => {
    ({ id: settingsId, policy: previousPolicy, localAuthEnabled: previousLocalAuthEnabled } = await readLockoutPolicy(request));
    userId = await ensureLockedUser(request);
  });

  test.beforeEach(async ({ request }) => {
    // A previous run may have left the account locked
    await setAccountActive(request, userId);
  });

  test.afterAll(async ({ request }) => {
    await setAccountActive(request, userId);
    await updateLockoutPolicy(request, settingsId, previousPolicy, previousLocalAuthEnabled);
  });

  test('should lock the account for the lock duration, until an administrator unlocks it', async ({ browser, request }, testInfo) => {
    await updateLockoutPolicy(request, settingsId, {
      local_auth_lockout_enabled: true,
      local_auth_lockout_max_attempts: MAX_ATTEMPTS,
      local_auth_lockout_admin_max_attempts: MAX_ATTEMPTS,
      local_auth_lockout_final_action: 'temporary',
      local_auth_lockout_window: 15,
      local_auth_lockout_duration: 15,
    });
    const { context, page, loginForm } = await openLoginPage(browser, testInfo);

    // No lock before the maximum number of attempts
    for (let attempt = 1; attempt < MAX_ATTEMPTS; attempt += 1) {
      await attemptLogin(page, loginForm, WRONG_PASSWORD, BAD_LOGIN_MESSAGE);
    }
    // The last attempt locks the account, with the remaining time
    await attemptLogin(page, loginForm, WRONG_PASSWORD, TEMPORARY_LOCK_MESSAGE);
    // During the lock, the right password is rejected too
    await attemptLogin(page, loginForm, LOCKED_USER.password, TEMPORARY_LOCK_MESSAGE);
    // A temporary lock does not change the account status
    expect(await readAccountStatus(request, userId)).toBe('Active');

    // The form cannot send Active again for an Active account: the administrator ends the lock with the API
    await setAccountActive(request, userId);
    await waitForLoginRateLimit(page);
    await loginForm.login(LOCKED_USER.email, LOCKED_USER.password);
    await context.close();
  });

  test('should set the account to Locked, until an administrator sets it back to Active', async ({ browser, page, request }, testInfo) => {
    await updateLockoutPolicy(request, settingsId, {
      local_auth_lockout_enabled: true,
      local_auth_lockout_max_attempts: MAX_ATTEMPTS,
      local_auth_lockout_admin_max_attempts: MAX_ATTEMPTS,
      local_auth_lockout_final_action: 'permanent',
      local_auth_lockout_window: 15,
      local_auth_lockout_duration: 15,
    });
    const { context, page: userPage, loginForm } = await openLoginPage(browser, testInfo);

    for (let attempt = 1; attempt < MAX_ATTEMPTS; attempt += 1) {
      await attemptLogin(userPage, loginForm, WRONG_PASSWORD, BAD_LOGIN_MESSAGE);
    }
    await attemptLogin(userPage, loginForm, WRONG_PASSWORD, PERMANENT_LOCK_MESSAGE);
    await attemptLogin(userPage, loginForm, LOCKED_USER.password, PERMANENT_LOCK_MESSAGE);
    expect(await readAccountStatus(request, userId)).toBe('Locked');

    // The administrator unlocks the account from its edition form
    await page.goto(`/dashboard/settings/accesses/users/${userId}`);
    await new UserPage(page).getEditButton().click();
    const accountStatus = new SelectFieldPageModel(page, 'Account Status', false);
    await expect(accountStatus.getInput()).toHaveText('Locked');
    await accountStatus.selectOption('Active');
    await expect.poll(() => readAccountStatus(request, userId)).toBe('Active');

    // The failed attempts were reset with the lock: the user logs in again
    await waitForLoginRateLimit(userPage);
    await loginForm.login(LOCKED_USER.email, LOCKED_USER.password);
    await context.close();
  });
});
