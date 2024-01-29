import { expect, test } from '@playwright/test';
import { login } from "../common/login";
import { LoginPage } from "../model/login.pageModel";
import { ReportPage } from "../model/report.pageModel";

  test('Create a new report page', async ({ page }) => {
    const reportPage = new ReportPage(page);
    await login(page);
    await page.getByLabel('Analyses').click();
    await page.getByRole('link', { name: 'Reports' });
    await expect(reportPage.getReportPage()).toBeVisible();
    await page.getByLabel('Add', { exact: true }).click()
    await page.getByLabel('Name').click();
    await page.getByLabel('Name').fill('Test e2e');
    await page.getByRole('button', { name: 'Create' }).click();
    await page.getByRole('link', { name: 'Reports' });
    await page.getByRole('link', { name: 'Test e2e Unknown - admin No' }).first().click();
    await page.getByRole('heading', { name: 'Entity details' });

  });
