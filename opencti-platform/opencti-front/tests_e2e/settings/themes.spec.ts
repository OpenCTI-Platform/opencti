import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';

const openThemeEditMenu = async (themeName: string, page: Page) => {
  await page
    .getByTestId(`${themeName}-popover`)
    .click();
  await page
    .getByRole('menuitem', { name: 'Update' })
    .click();
};

/**
 * MUST create custom theme.
 * MUST check visibility in list lines.
 * MUST select custom theme and validate its usage.
 * MUST edit custom theme.
 * MUST delete custom theme.
 */
test('Custom theme creation, edition, and deletion', async ({ page }) => {
  const THEME = {
    name: `${new Date().toISOString()} Test Theme`,
    theme_background: '#e72a2a',
    theme_paper: '#8f3939',
    theme_nav: '#bb4545',
    theme_primary: '#460707',
    theme_secondary: '#b88f8f',
    theme_accent: '#5d4e4e',
    theme_text_color: '#353131',
    theme_logo: 'https://www.google.com/images/branding/googlelogo/1x/googlelogo_light_color_272x92dp.png',
  };

  // Navigate to Settings
  const leftBarPage = new LeftBarPage(page);
  await page.goto('/');
  await leftBarPage.open();
  await leftBarPage.clickOnMenu('Settings', 'Parameters');

  // Create theme
  await page.getByTestId('create-theme-btn').click();
  for (const [key, value] of Object.entries(THEME)) {
    await page.locator(`input[name="${key}"]`).fill(value);
  }
  await page.getByRole('button', { name: 'Create' }).click();

  // Assert exists on screen
  expect(await page.getByText(THEME.name).count() > 0);

  // Select system default
  await page.locator('#mui-component-select-platform_theme').click();
  await page.getByTestId(`${THEME.name}-li`).click();
  await page.waitForTimeout(1000);
  let logoSrc = await page
    .getByRole('link', { name: 'logo' })
    .locator('img').getAttribute('src');
  expect(logoSrc).not.toContain('static/images/logo');

  // Edit theme
  openThemeEditMenu(THEME.name, page);
  await page
    .locator('input[name="theme_logo"]')
    .fill('');
  for (const closeBtn of await page.getByLabel('Close').all()) {
    closeBtn.click();
  }
  await page.waitForTimeout(1000);
  logoSrc = await page
    .getByRole('link', { name: 'logo' })
    .locator('img').getAttribute('src');
  expect(logoSrc).toContain('static/images/logo');

  // Select Dark theme again to delete custom theme
  await page.locator('#mui-component-select-platform_theme').click();
  await page.getByTestId('Dark-li').click();
  await page.waitForTimeout(1000);

  // Delete theme
  await page.getByTestId(`${THEME.name}-popover`).click();
  await page.getByLabel('Delete').click();
  await page.getByRole('button', { name: 'Confirm' }).click();
  expect(await page.getByText('Theme successfully deleted').count() > 0);
});

/**
 * MUST ensure cannot delete system theme.
 */
test('Cannot delete system theme', async ({ page }) => {
  // Navigate to Settings
  const leftBarPage = new LeftBarPage(page);
  await page.goto('/');
  await leftBarPage.open();
  await leftBarPage.clickOnMenu('Settings', 'Parameters');

  await page.getByTestId('Light-popover').click();
  expect(await page.getByLabel('Delete').count() === 0);
});
