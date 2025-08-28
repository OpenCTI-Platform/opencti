import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import { awaitUntilCondition } from '../utils';

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
  await page
    .locator('input[name="platform_theme_dark_logo"]')
    .fill('');
  await page
    .locator('input[name="platform_theme_dark_logo"]')
    .press('Tab');

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
