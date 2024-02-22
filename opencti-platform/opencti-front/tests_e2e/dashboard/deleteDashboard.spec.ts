import { expect, test } from "../fixtures/baseFixtures";
import { DashboardPage } from "../model/dashboard.pageModel";

test.skip('Create a new dashboard page and delete it', async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  await page.goto('/dashboard/workspaces/dashboards');
  await dashboardPage.addNewDashboard();
  await dashboardPage.getDashboardNameInput().click();
  await dashboardPage.getDashboardNameInput().fill('Test delete dashboard e2e');
  await dashboardPage.getCreateDashboardButton()

  await page.getByRole('button', { name: 'Launch' }).click();
  await page.goto('/dashboard/workspaces/dashboards');
  expect(page.getByRole('link', { name: 'Test delete dashboard Test e2e' }).count()).toEqual(0);
})