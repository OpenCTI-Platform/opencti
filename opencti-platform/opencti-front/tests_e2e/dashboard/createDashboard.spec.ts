import { expect, test } from '../fixtures/baseFixtures';
import DashboardPage from '../model/dashboard.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import DashboardFormPage from '../model/dashboardForm.pageModel';

test('Create a new dashboard page', async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  const dashboardDetailsPage = new DashboardDetailsPage(page);
  const dashboardForm = new DashboardFormPage(page);
  await page.goto('/dashboard/workspaces/dashboards');
  await dashboardPage.addNewDashboard().click();
  await dashboardForm.fillNameInput('Test e2e');
  await dashboardPage.getCreateDashboardButton().click();
  await dashboardPage.getItemFromList('Test e2e').click();
  await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();
  await dashboardDetailsPage.addNewDashboardTag().click();
  await dashboardForm.fillTagInput('Add Test Tag e2e');
  await dashboardForm.getTagInput().press('Enter');
  await expect(dashboardDetailsPage.getTag('Add Test Tag e2e')).toBeVisible();
  await dashboardDetailsPage.openPopUpButton().click();
  await dashboardDetailsPage.getDeleteButton().click();
  await dashboardDetailsPage.getDelete().click();
  await page.goto('/dashboard/workspaces/dashboards');
  await expect(page.getByRole('link', { name: 'Test e2e' })).toBeHidden();
});
