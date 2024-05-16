import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';

test('Check EE activation', async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);

  await page.goto('/');
  await leftBarPage.open();
  await leftBarPage.clickOnMenu('Settings', 'Parameters');

  await page.getByRole('button', { name: 'Enable Enterprise Edition' }).click();
  await expect(page.getByRole('heading', { name: 'OpenCTI Enterprise Edition (' })).toBeVisible();
  await page.getByLabel('I have read and agree to the').check();
  await page.getByRole('button', { name: 'Enable' }).click();
  await expect(page.getByText(/^Enterprise$/)).toBeVisible();
  await page.getByRole('button', { name: 'Disable Enterprise Edition' }).click();
});

test('Check Logo replacement', async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);

  await page.goto('/');
  await leftBarPage.open();
  await leftBarPage.clickOnMenu('Settings', 'Parameters');

  let logoSrc = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
  expect(logoSrc).toContain('static/images/logo');
  await page
    .locator('input[name="platform_theme_dark_logo"]')
    .fill('https://www.google.com/images/branding/googlelogo/1x/googlelogo_light_color_272x92dp.png');
  await page
    .locator('input[name="platform_theme_dark_logo"]')
    .press('Tab');
  await page.waitForTimeout(1000);
  logoSrc = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
  expect(logoSrc).not.toContain('static/images/logo');
  await page
    .locator('input[name="platform_theme_dark_logo"]')
    .fill('');
  await page
    .locator('input[name="platform_theme_dark_logo"]')
    .press('Tab');
  await page.waitForTimeout(1000);
  logoSrc = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
  expect(logoSrc).toContain('static/images/logo');
});
