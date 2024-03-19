import { expect, test as setup } from './fixtures/baseFixtures';
import DashboardPage from './model/dashboard.pageModel';
import LoginPage from './model/login.pageModel';

const authFile = 'tests_e2e/.setup/.auth/user.json';
const prepLogoutFile = 'tests_e2e/.setup/.auth/logout-user.json';

const analystCapabilities = ['Delete knowledge', 'Delete exploration', 'Generate knowledge export', 'Import knowledge', 'Upload knowledge files', 'Manage authorized members', 'Restrict organization access', 'Access to collaborative creation', 'Ask for knowledge enrichment'];

setup('authenticate', async ({ page, request }) => {
  const dashboardPage = new DashboardPage(page);
  const loginPage = new LoginPage(page);
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();
  // End of authentication steps.
  await page.context().storageState({ path: authFile });

  const response = await request.post('http://localhost:3000/graphql', {
    data: {
      query: `mutation {
        roleAdd(input:{
            name:"Analyst"
        }){
            id
            name
        }
    }`,
    },
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer d434ce02-e58e-4cac-8b4c-42bf16748e84',
    },
  });
  expect(response.ok()).toBeTruthy();
  expect(response.status()).toBe(200);
  expect((await response.json()).data.roleAdd.name).toBe('Analyst');
});

setup('authenticate for logout user', async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  const loginPage = new LoginPage(page);
  await loginPage.login();
  await expect(dashboardPage.getPage()).toBeVisible();
  // End of authentication steps.
  await page.context().storageState({ path: prepLogoutFile });
});
