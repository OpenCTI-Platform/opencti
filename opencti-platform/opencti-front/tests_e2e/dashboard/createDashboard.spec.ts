import { expect, test } from "../fixtures/baseFixtures";
import { DashboardPage } from "../model/dashboard.pageModel";
import { DashboardDetailsPage } from "../model/dashboardDetails.pageModel";
import { DashboardFormPage } from "../model/dashboardForm.pageModel";
 test('Create a new dashboard page', async ({ page }) => {
   const dashboardPage = new DashboardPage(page);
   const dashboardDetailsPage = new DashboardDetailsPage(page);
   const dashboardForm = new DashboardFormPage(page);
   await page.goto('/dashboard/workspaces/dashboards');
   await dashboardPage.addNewDashboard();
   await dashboardForm.fillNameInput('Test e2e');
   await dashboardPage.getCreateDashboardButton().click();
   await dashboardPage.getItemFromList('Test e2e Unknown - admin No').click();
   await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();
 })