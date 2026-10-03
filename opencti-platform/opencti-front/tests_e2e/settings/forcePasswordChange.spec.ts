import type { APIRequestContext } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import LoginFormPageModel from '../model/form/loginForm.pageModel';

const TEST_USER_EMAIL = 'test-password-expiry@filigran.test';
const TEST_USER_PASSWORD = 'TestPassword1!';
const TEST_USER_NAME = 'TestPasswordExpiry';

const HISTORY_USER = {
  name: 'TestPasswordHistory',
  email: 'test-password-history@filigran.test',
  password: 'HistoryPassword1!',
};

const CHANGE_PASSWORD_PATH = '/dashboard/change-password';

/**
 * Run a GraphQL mutation/query as the admin (uses the stored auth session).
 */
const graphql = async (request: APIRequestContext, query: string, variables?: Record<string, unknown>) => {
  const response = await request.post('/graphql', {
    data: variables ? { query, variables } : { query },
  });
  return JSON.parse((await response.body()).toString());
};

/**
 * Find a user by email and return their id.
 */
const findUserIdByEmail = async (request: APIRequestContext, email: string): Promise<string | null> => {
  const result = await graphql(request, `
    query {
      users(search: "${email}") {
        edges { node { id, user_email } }
      }
    }
  `);
  const user = result.data.users.edges.find((e: { node: { id: string; user_email: string } }) => e.node.user_email === email);
  return user ? user.node.id : null;
};

/**
 * Create the test user if it doesn't exist.
 */
const ensureTestUser = async (
  request: APIRequestContext,
  { name, email, password } = { name: TEST_USER_NAME, email: TEST_USER_EMAIL, password: TEST_USER_PASSWORD },
): Promise<string> => {
  let userId = await findUserIdByEmail(request, email);
  if (!userId) {
    const result = await graphql(request, `
      mutation {
        userAdd(input: {
          name: "${name}",
          user_email: "${email}",
          password: "${password}",
        }) { id }
      }
    `);
    userId = result.data.userAdd.id;
  }
  return userId!;
};

/**
 * Set password_valid_until on a user (admin operation).
 */
const setPasswordValidUntil = async (request: APIRequestContext, userId: string, value: string | null) => {
  const valueStr = value ? `"${value}"` : 'null';
  await graphql(request, `
    mutation {
      userEdit(id: "${userId}") {
        fieldPatch(input: {
          key: "password_valid_until",
          value: [${valueStr}],
        }) { id, password_valid_until }
      }
    }
  `);
};

/**
 * Set the number of recent passwords that cannot be reused, leaving the other local policies as they are.
 */
const setPasswordHistoryCount = async (request: APIRequestContext, count: number) => {
  const { data } = await graphql(request, 'query { settings { id } }');
  await graphql(request, `
    mutation ($id: ID!, $input: LocalAuthConfigInput!) {
      settingsEdit(id: $id) {
        updateLocalAuth(input: $input) { id }
      }
    }
  `, { id: data.settings.id, input: { enabled: true, password_policy_history_count: count } });
};

test.describe('Force password change - navigation blocking', { tag: ['@ce', '@groupff'] }, () => {
  let testUserId: string;

  test.beforeEach(async ({ request }) => {
    // Ensure test user exists and reset password_valid_until to null (not expired)
    testUserId = await ensureTestUser(request);
    await setPasswordValidUntil(request, testUserId, null);
  });

  test.afterEach(async ({ request }) => {
    // Always reset password_valid_until to null to avoid leaving a broken state
    if (testUserId) {
      await setPasswordValidUntil(request, testUserId, null);
    }
  });

  test('should show force password change form when password is expired', async ({ page, request }) => {
    const loginPage = new LoginFormPageModel(page);

    // Set password_valid_until to a past date (expired)
    const pastDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    await setPasswordValidUntil(request, testUserId, pastDate);

    // Log in as the test user (clear existing session first)
    await page.context().clearCookies();
    await page.goto('/');
    await loginPage.login(TEST_USER_EMAIL, TEST_USER_PASSWORD);

    // Should show the force password change form on the login page (not redirect)
    await expect(page.getByLabel('New password')).toBeVisible({ timeout: 30000 });
    await expect(page.getByLabel('Confirmation')).toBeVisible();
  });

  test('should block direct navigation to private routes when password is expired', async ({ page, request }) => {
    const loginPage = new LoginFormPageModel(page);

    // Set password_valid_until to a past date (expired)
    const pastDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    await setPasswordValidUntil(request, testUserId, pastDate);

    // Log in as the test user (session will be created despite the error)
    await page.context().clearCookies();
    await page.goto('/');
    await loginPage.login(TEST_USER_EMAIL, TEST_USER_PASSWORD);

    // Wait for force password change form to appear (session is now created)
    await expect(page.getByLabel('New password')).toBeVisible({ timeout: 30000 });

    // Navigate directly to a private route — since session exists but password is expired,
    // Root.tsx should redirect to change-password
    await page.goto('/dashboard/settings');
    await expect(page).toHaveURL(new RegExp(CHANGE_PASSWORD_PATH));

    // Try another route
    await page.goto('/dashboard/analyses');
    await expect(page).toHaveURL(new RegExp(CHANGE_PASSWORD_PATH));
  });

  test('should NOT redirect when password_valid_until is in the future', async ({ page, request }) => {
    const loginPage = new LoginFormPageModel(page);

    // Set password_valid_until to a future date (not expired)
    const futureDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    await setPasswordValidUntil(request, testUserId, futureDate);

    // Log in as the test user
    await page.context().clearCookies();
    await page.goto('/');
    await loginPage.login(TEST_USER_EMAIL, TEST_USER_PASSWORD);

    // Should land on the dashboard, NOT on change-password
    await page.waitForURL('**/dashboard', { timeout: 30000 });
    expect(page.url()).not.toContain(CHANGE_PASSWORD_PATH);
  });

  test('should NOT redirect when password_valid_until is null', async ({ page, request }) => {
    const loginPage = new LoginFormPageModel(page);

    // Ensure password_valid_until is null (no expiry)
    await setPasswordValidUntil(request, testUserId, null);

    // Log in as the test user
    await page.context().clearCookies();
    await page.goto('/');
    await loginPage.login(TEST_USER_EMAIL, TEST_USER_PASSWORD);

    // Should land on the dashboard
    await page.waitForURL('**/dashboard', { timeout: 30000 });
    expect(page.url()).not.toContain(CHANGE_PASSWORD_PATH);
  });
});

test.describe('Force password change - password history', { tag: ['@ce', '@groupff'] }, () => {
  let historyUserId: string;

  test.beforeEach(async ({ request }) => {
    historyUserId = await ensureTestUser(request, HISTORY_USER);
    await setPasswordHistoryCount(request, 2);
    const pastDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    await setPasswordValidUntil(request, historyUserId, pastDate);
  });

  test.afterEach(async ({ request }) => {
    // 0 also deletes the password histories recorded meanwhile
    await setPasswordHistoryCount(request, 0);
    if (historyUserId) {
      await setPasswordValidUntil(request, historyUserId, null);
    }
  });

  test('should refuse the current password and keep the user on the form', async ({ page }) => {
    const loginPage = new LoginFormPageModel(page);
    await page.context().clearCookies();
    await page.goto('/');
    await loginPage.login(HISTORY_USER.email, HISTORY_USER.password);

    await expect(page.getByText('Must be different from your last 2 passwords')).toBeVisible({ timeout: 30000 });
    await page.getByLabel('New password').fill(HISTORY_USER.password);
    await page.getByLabel('Confirmation').fill(HISTORY_USER.password);
    await page.getByRole('button', { name: 'Update' }).click();

    // Under the field, and in the notification
    await expect(page.getByText('This password has already been used recently. Please choose a different one.').first()).toBeVisible();
    await expect(page.getByLabel('New password')).toHaveValue('');
    await expect(page.getByLabel('Confirmation')).toHaveValue('');
  });
});
