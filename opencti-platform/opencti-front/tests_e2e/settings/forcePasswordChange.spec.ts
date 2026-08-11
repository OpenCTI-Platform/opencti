import { expect, test } from '../fixtures/baseFixtures';
import LoginFormPageModel from '../model/form/loginForm.pageModel';

const TEST_USER_EMAIL = 'test-password-expiry@filigran.test';
const TEST_USER_PASSWORD = 'TestPassword1!';
const TEST_USER_NAME = 'TestPasswordExpiry';

const CHANGE_PASSWORD_PATH = '/dashboard/change-password';

/**
 * Run a GraphQL mutation/query as the admin (uses the stored auth session).
 */
const graphql = async (request: any, query: string, variables?: Record<string, unknown>) => {
  const response = await request.post('/graphql', {
    data: variables ? { query, variables } : { query },
  });
  return JSON.parse((await response.body()).toString());
};

/**
 * Find a user by email and return their id.
 */
const findUserIdByEmail = async (request: any, email: string): Promise<string | null> => {
  const result = await graphql(request, `
    query {
      users(search: "${email}") {
        edges { node { id, user_email } }
      }
    }
  `);
  const user = result.data.users.edges.find((e: any) => e.node.user_email === email);
  return user ? user.node.id : null;
};

/**
 * Create the test user if it doesn't exist.
 */
const ensureTestUser = async (request: any): Promise<string> => {
  let userId = await findUserIdByEmail(request, TEST_USER_EMAIL);
  if (!userId) {
    const result = await graphql(request, `
      mutation {
        userAdd(input: {
          name: "${TEST_USER_NAME}",
          user_email: "${TEST_USER_EMAIL}",
          password: "${TEST_USER_PASSWORD}",
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
const setPasswordValidUntil = async (request: any, userId: string, value: string | null) => {
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
