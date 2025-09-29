import { test, expect } from '../fixtures/baseFixtures';

test.describe('Ask Ariane button alignment', () => {
  test('should maintain consistent Ask Ariane alignment when toggling menu', async ({ page }) => {
    // Issue #12546: VALIDATION TEST: Verify the fix works

    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Ensure menu starts collapsed
    const chevronIcon = page.getByTestId('ChevronRightIcon');

    if (await chevronIcon.count() === 0) {
      await page.getByTestId('ChevronLeftIcon').click();
      await page.waitForTimeout(50);
    }

    // Measure Ask Ariane icon position in initial collapsed state
    const askArianeInitialCollapsed = page.locator('[data-testid="ArianeButtonCollapsed"] svg');

    await expect(askArianeInitialCollapsed).toBeVisible();
    const initialCollapsedBox = await askArianeInitialCollapsed.boundingBox();
    expect(initialCollapsedBox).not.toBeNull();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const { x: initialCollapsedIconX, y: initialCollapsedIconY } = initialCollapsedBox!;

    // Toggle to expanded and measure
    await page.getByTestId('ChevronRightIcon').click();
    await page.waitForTimeout(50);

    const askArianeExpanded = page.locator('[data-testid="ArianeButtonExpended"] svg');
    await expect(askArianeExpanded).toBeVisible();
    const expandedBox = await askArianeExpanded.boundingBox();
    expect(expandedBox).not.toBeNull();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const { x: expandedIconX, y: expandedIconY } = expandedBox!;

    // ASSERTION: After fix, positions should be much more consistent
    const collapsedToExpandedDifferenceX = Math.abs(initialCollapsedIconX - expandedIconX);
    const collapsedToExpandedDifferenceY = Math.abs(initialCollapsedIconY - expandedIconY);

    // The fix should keep the icon alignment consistent (difference should be minimal)
    expect(collapsedToExpandedDifferenceX).toBeLessThan(1); // Allow some tolerance for visual consistency
    expect(collapsedToExpandedDifferenceY).toBeLessThan(1); // Allow some tolerance for visual consistency

    // Verify toggle back to collapsed works correctly
    await page.getByTestId('ChevronLeftIcon').click();
    await page.waitForTimeout(50);

    const askArianeFinalCollapsed = page.locator('[data-testid="ArianeButtonCollapsed"] svg');
    await expect(askArianeFinalCollapsed).toBeVisible();
    const finalCollapsedBox = await askArianeFinalCollapsed.boundingBox();
    expect(finalCollapsedBox).not.toBeNull();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const { x: finalCollapsedIconX, y: finalCollapsedIconY } = finalCollapsedBox!;

    const collapsedToCollapsedDifferenceX = Math.abs(initialCollapsedIconX - finalCollapsedIconX);
    const collapsedToCollapsedDifferenceY = Math.abs(initialCollapsedIconY - finalCollapsedIconY);

    // Verify consistency when toggling back to collapsed
    expect(collapsedToCollapsedDifferenceX).toBeLessThan(1); // Allow some tolerance for visual consistency
    expect(collapsedToCollapsedDifferenceY).toBeLessThan(1); // Allow some tolerance for visual consistency
  });
});
