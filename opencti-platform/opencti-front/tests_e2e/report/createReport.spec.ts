import { test } from '@playwright/test';
import { login } from "../common/login";

  test('Create a new report page', async ({ page }) => {
    await login(page);
    await page.getByLabel('Analyses').click();
    await page.getByRole('link', { name: 'Reports' });
    await page.getByLabel('Add', { exact: true }).click()
    await page.getByLabel('Name').click();
    await page.getByLabel('Name').fill('Test e2e');
    await page.getByRole('button', { name: 'Create' }).click();
    await page.getByRole('link', { name: 'Reports' });
    await page.getByRole('link', { name: 'Test e2e Unknown - admin No' }).first().click();
    await page.getByRole('heading', { name: 'Entity details' });
    
  });
