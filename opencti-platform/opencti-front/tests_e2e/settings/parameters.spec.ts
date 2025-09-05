import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import { awaitUntilCondition } from '../utils';

const openThemeEditMenu = async (themeName: string, page: Page) => {
  await page
    .getByTestId(`${themeName}-popover`)
    .click();
  await page
    .getByRole('menuitem', { name: 'Update' })
    .click();
};

test('Check Logo replacement', async ({ page }) => {
  const leftBarPage = new LeftBarPage(page);

  await page.goto('/');
  await leftBarPage.open();
  await leftBarPage.clickOnMenu('Settings', 'Parameters');

  // Set platform theme to be Dark
  await page.locator('#mui-component-select-platform_theme').click();
  await page.getByTestId('Dark-li').click();

  let logoSrc = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
  expect(logoSrc).toContain('static/images/logo');

  // Set Dark theme logo to the Google logo
  openThemeEditMenu('Dark', page);
  await page
    .locator('input[name="theme_logo"]')
    .fill('https://www.google.com/images/branding/googlelogo/1x/googlelogo_light_color_272x92dp.png');
  await page
    .getByLabel('Close')
    .click();
  const isLogoChanged = async () => {
    await page.reload();
    const logoSrcChangedToGoogle = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
    if (logoSrcChangedToGoogle) {
      return !logoSrcChangedToGoogle.endsWith('static/images/logo');
    }
    return false;
  };
  await awaitUntilCondition(isLogoChanged);

  logoSrc = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
  expect(logoSrc).not.toContain('static/images/logo');

  // Reset logo
  openThemeEditMenu('Dark', page);
  await page
    .locator('input[name="theme_logo"]')
    .fill('');
  await page
    .getByLabel('Close')
    .click();
  await page.waitForTimeout(1000);

  const isLogoBackToDefault = async () => {
    await page.reload();
    const logoSrcChangedToDefault = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
    if (logoSrcChangedToDefault) {
      return logoSrcChangedToDefault.endsWith('static/images/logo');
    }
    return false;
  };
  await awaitUntilCondition(isLogoBackToDefault);
  logoSrc = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
  expect(logoSrc).toContain('static/images/logo');
});
