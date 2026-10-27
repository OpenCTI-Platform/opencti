import { expect, test } from '../fixtures/baseFixtures';
import SettingsFiligranExperiencePage from '../model/settingsFiligranExperience.pageModel';

// The wizard needs the CONFIG_PRESET flag, on for the `@groupff` e2e group (`dev_features: '["*"]'`).
// The automatic display is disabled on the e2e platform (APP__BOOTSTRAP_WIZARD__ENABLED=false), only the manual entry is tested.
test.describe('Bootstrap wizard', { tag: ['@ce', '@groupff'] }, () => {
  test('should open from Settings > Experience and close with Skip', async ({ page }) => {
    const experiencePage = new SettingsFiligranExperiencePage(page);
    await experiencePage.goto();
    await expect(experiencePage.getPage('experience-page')).toBeVisible();
    await page.getByRole('button', { name: 'Import Bootstrap Platform Bundle' }).click();
    await expect(page.getByText('Set up your platform')).toBeVisible();
    await page.getByRole('button', { name: 'Skip' }).click();
    await expect(page.getByText('Set up your platform')).not.toBeVisible();
  });
});
