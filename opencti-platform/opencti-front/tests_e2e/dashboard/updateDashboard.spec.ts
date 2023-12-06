import { expect, test } from '../fixtures/baseFixtures';
import DashboardPage from '../model/dashboard.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import DashboardFormPage from '../model/dashboardForm.pageModel';

test('Create a new dashboard page and test update', async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  const dashboardDetailsPage = new DashboardDetailsPage(page);
  const dashboardForm = new DashboardFormPage(page);
  await page.goto('/dashboard/workspaces/dashboards');
  await dashboardPage.addNewDashboard().click();
  await dashboardForm.fillNameInput('Test Update e2e');
  await dashboardPage.getCreateDashboardButton().click();
  await dashboardPage.getItemFromList('Test Update e2e').click();
  await dashboardDetailsPage.openPopUpButton().click();
  await dashboardDetailsPage.getEditButton().click();
  await dashboardForm.fillNameInput('Modification Test Update e2e');
  await dashboardForm.getCloseButton().click();
  await expect(dashboardDetailsPage.getTitle('Modification Test Update e2e')).toBeVisible();
});
