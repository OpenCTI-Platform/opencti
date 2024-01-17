import { test, expect } from '@playwright/test';
import { LoginPage } from "./model/login.pageModel";
import { DashboardPage } from "./model/dashboard.pageModel";

  test('Log to Filigran App', async ({ page }) => {
    const loginPage = new LoginPage(page);
    const dashboardPage = new DashboardPage(page);
    await page.goto('http://localhost:3000/');
    await expect(loginPage.getLogo()).toBeVisible();
    await page.getByLabel('Login').click();
    await page.getByLabel('Login').fill('admin@opencti.io');
    await page.getByLabel('Password').click();
    await page.getByLabel('Password').fill('admin');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(dashboardPage.getDashboardButton()).toBeVisible()
  });
