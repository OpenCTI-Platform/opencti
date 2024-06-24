import { expect, test } from '../fixtures/baseFixtures';
import DashboardPage from '../model/dashboard.pageModel';
import DashboardDetailsPage from '../model/dashboardDetails.pageModel';
import DashboardFormPage from '../model/form/dashboardForm.pageModel';
import WidgetFormPage from 'tests_e2e/model/form/widgetForm.pageModel';

test('Create a new dashboard page and test create widget', async ({ page }) => {
  const dashboardPage = new DashboardPage(page);
  const dashboardDetailsPage = new DashboardDetailsPage(page);
  const dashboardForm = new DashboardFormPage(page);
  const widgetForm = new WidgetFormPage(page);
  await page.goto('/dashboard/workspaces/dashboards');
  await dashboardPage.openButtonModal().hover();
  await dashboardPage.addNewDashboard().click();
  await dashboardForm.fillNameInput('Test Create Widget e2e');
  await dashboardPage.getCreateDashboardButton().click();
  await dashboardPage.getItemFromList('Test Create Widget e2e').click();
  await expect(dashboardDetailsPage.getDashboardDetailsPage()).toBeVisible();
  await dashboardDetailsPage.getWidgetActionSelection().click();
  await dashboardDetailsPage.getCreateWidget().click();
  await dashboardDetailsPage.getCreateWidgetButton().click();
  await widgetForm.getTextWidgetButton().click();
  await widgetForm.getTextWidgetTitleInput().click();
  await widgetForm.fillTextWidgetTitleInput('Test Create Widget');
  await widgetForm.getTextWidgetContentInput().click();
  await widgetForm.fillTextWidgetContentInput('Test Widget Content');
  await widgetForm.getWidgetSubmitButton().click()
  await expect(dashboardDetailsPage.getTextWidget('Test Widget Content')).toBeVisible();
});
