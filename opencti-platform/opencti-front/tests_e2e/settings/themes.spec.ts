import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import { awaitUntilCondition } from 'tests_e2e/utils';

const openThemeEditMenu = async (themeName: string, page: Page) => {
  await page
    .getByTestId(`${themeName}-popover`)
    .click();
  await page
    .getByRole('menuitem', { name: 'Update' })
    .click();
};

/**
 * Edits the logo URL of a theme through the edition drawer.
 * The logo field is persisted on blur, so we explicitly blur the input and
 * wait for the update to complete before closing the drawer. Otherwise a
 * subsequent navigation/reload could abort the in-flight mutation and the
 * change would never be persisted.
 */
const editThemeLogo = async (themeName: string, page: Page, logoUrl: string) => {
  await openThemeEditMenu(themeName, page);
  const logoInput = page.locator('input[name="theme_logo"]');
  await logoInput.fill(logoUrl);
  await logoInput.blur();
  await expect(page.getByText('Successfully updated theme').first()).toBeVisible();
  for (const closeBtn of await page.getByLabel('Close').all()) {
    await closeBtn.click();
  }
};

/**
 * MUST create custom theme.
 * MUST check visibility in list lines.
 * MUST select custom theme and validate its usage.
 * MUST edit custom theme.
 * MUST change custom theme logo.
 * MUST delete custom theme.
 */
test('Custom theme creation, logo edition, and deletion', { tag: ['@ce'] }, async ({ page }) => {
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

  // disable on purpose because we want that fill to be sequentially

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
  expect(logoSrc).toContain('googlelogo');

  // Edit theme
  // edit the logo url by removing the url
  await editThemeLogo(THEME.name, page, '');
  await page.waitForTimeout(1000);

  // expect to have the default dark logo
  logoSrc = await page
    .getByRole('link', { name: 'logo' })
    .locator('img').getAttribute('src');
  expect(logoSrc).toContain('logo_text_dark');

  // Set theme logo to the Google logo
  await editThemeLogo(THEME.name, page, THEME.theme_logo);
  const isLogoChanged = async () => {
    await page.reload();
    const logoSrcChangedToGoogle = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
    if (logoSrcChangedToGoogle) {
      return logoSrcChangedToGoogle.includes('googlelogo');
    }
    return false;
  };
  await awaitUntilCondition(isLogoChanged);

  logoSrc = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
  expect(logoSrc).toContain('googlelogo');

  // Reset logo
  await editThemeLogo(THEME.name, page, '');
  await page.waitForTimeout(1000);

  const isLogoBackToDefault = async () => {
    await page.reload();
    const logoSrcChangedToDefault = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
    if (logoSrcChangedToDefault) {
      return logoSrcChangedToDefault.includes('logo_text_dark');
    }
    return false;
  };
  await awaitUntilCondition(isLogoBackToDefault);
  logoSrc = await page.getByRole('link', { name: 'logo' }).locator('img').getAttribute('src');
  expect(logoSrc).toContain('logo_text_dark');

  // Select Dark theme again to delete custom theme
  await page.locator('#mui-component-select-platform_theme').click();
  await page.getByTestId('Filigran Dark-li').click();
  await page.waitForTimeout(1000);

  // Delete custom theme
  await page.getByTestId(`${THEME.name}-popover`).click();
  await page.getByLabel('Delete').click();
  await page.getByRole('button', { name: 'Confirm' }).click();
  expect(await page.getByText('Theme successfully deleted').count() > 0);
});

/**
 * MUST ensure cannot delete system theme.
 * MUST ensure cannot update system theme.
 */
test('Cannot delete or update system theme', { tag: ['@ce'] }, async ({ page }) => {
  // Navigate to Settings
  const leftBarPage = new LeftBarPage(page);
  await page.goto('/');
  await leftBarPage.open();
  await leftBarPage.clickOnMenu('Settings', 'Parameters');

  await page.getByTestId('Filigran Light-popover').click();
  expect(await page.getByLabel('Delete').count() === 0);
  expect(await page.getByLabel('Update').count() === 0);
});
