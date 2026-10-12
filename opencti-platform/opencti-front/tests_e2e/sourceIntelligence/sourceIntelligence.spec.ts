import { expect, test } from '../fixtures/baseFixtures';

const SOURCES_URL = '/dashboard/integrations/sources';

/**
 * Content of the test
 * -------------------
 * Open Integrations > Sources, read the status header and the counters, and request a recomputation
 * Navigate through the leaderboard, overlap, collection gaps and recommendations views
 * Open the settings under Settings > Customization from the Sources area
 * Open the scorecard page of a scored source when the manager already scored one
 * Edit a setting and restore it
 */
test('Source intelligence navigation and settings', { tag: ['@sourceIntelligence', '@mutation', '@ee'] }, async ({ page }) => {
  await page.goto('/dashboard/integrations/deployed');
  await page.getByTestId('integrations-tab-sources').click();
  await expect(page).toHaveURL(new RegExp(`${SOURCES_URL}`));
  await expect(page.getByTestId('source-intelligence-page')).toBeVisible();
  await expect(page.getByTestId('source-intelligence-status')).toBeVisible();
  await expect(page.getByTestId('source-intelligence-kpis')).toBeVisible();

  // region Recompute, offered unless a computation is running or already requested
  const recompute = page.getByTestId('source-intelligence-recompute');
  if (await recompute.isVisible()) {
    await recompute.click();
    await expect(page.getByText('The scorecards will be recomputed in the next minutes')).toBeVisible();
    await expect(recompute).toBeHidden();
  }
  // endregion

  // region Leaderboard and scorecard page
  await page.getByTestId('source-intelligence-tab-leaderboard').click();
  await expect(page.getByTestId('source-intelligence-leaderboard')).toBeVisible();
  const sourceLinks = page.getByTestId('source-intelligence-leaderboard').locator('a[href*="/dashboard/integrations/sources/source/"]');
  if (await sourceLinks.count() > 0) {
    await sourceLinks.first().click();
    await expect(page.getByTestId('source-detail-page')).toBeVisible();
    await expect(page.getByTestId('source-detail-value-score').or(page.getByTestId('source-detail-no-scorecard'))).toBeVisible();
    await page.goBack();
  }
  // endregion

  // region Overlap, gaps and recommendations
  await page.getByTestId('source-intelligence-tab-overlap').click();
  await expect(page.getByTestId('source-overlap-matrix').or(page.getByTestId('source-overlap-empty'))).toBeVisible();

  await page.getByTestId('source-intelligence-tab-gaps').click();
  await expect(page.getByTestId('collection-gaps')).toBeVisible();
  await expect(page.getByTestId('collection-gaps-list').or(page.getByTestId('collection-gaps-empty'))).toBeVisible();

  await page.getByTestId('source-intelligence-tab-recommendations').click();
  await expect(page.getByTestId('source-recommendations-inbox')).toBeVisible();
  await expect(page.getByTestId('source-recommendations-list').or(page.getByTestId('source-recommendations-empty'))).toBeVisible();
  // endregion

  // region Settings, under Settings > Customization
  await page.getByTestId('source-intelligence-settings').click();
  await expect(page).toHaveURL(/\/dashboard\/settings\/customization\/source_intelligence/);
  await expect(page.getByTestId('source-intelligence-settings-page')).toBeVisible();
  const form = page.getByTestId('source-intelligence-settings-form');
  await expect(form).toBeVisible();
  const submit = page.getByTestId('source-intelligence-settings-submit');
  await expect(submit).toBeDisabled();
  const overlapTop = form.locator('input[name="overlap_top"]');
  const initialValue = await overlapTop.inputValue();
  const nextValue = initialValue === '15' ? '16' : '15';
  await overlapTop.fill(nextValue);
  await expect(submit).toBeEnabled();
  await submit.click();
  await expect(page.getByText('Source intelligence settings saved')).toBeVisible();
  await expect(overlapTop).toHaveValue(nextValue);
  // Restore the initial value
  await overlapTop.fill(initialValue);
  await submit.click();
  await expect(overlapTop).toHaveValue(initialValue);
  await expect(submit).toBeDisabled();
  // endregion
});
