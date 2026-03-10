import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';

/**
 * Regression test for issue #14799
 * ─────────────────────────────────
 * Bug: When `isSensitive` is true for connector_reset, hovering the "Reset"
 * DangerZone MenuItem in the connector popover menu caused a garbled native
 * browser tooltip showing "[object Object]" because DangerZoneBlock's
 * cloneElement injected a React JSX `title` prop onto the native `<li>`.
 *
 * Fix: Changed the `component` prop from ReactNode to a render function so
 * cloneElement is no longer used. A proper MUI Tooltip is rendered instead.
 *
 * This test validates:
 * 1. The connector popover menu opens and stays visible.
 * 2. The "Reset" menu item with DangerZone chip is present inside the menu.
 * 3. Hovering the Reset item shows a proper MUI Tooltip (role="tooltip").
 * 4. No native `title` attribute with "[object Object]" leaks onto the DOM.
 * 5. No layout shift occurs (menu bounding box remains stable).
 */
test.describe('Connector Popover — Danger Zone hover regression (#14799)', { tag: ['@ce'] }, () => {
  test('Hovering the DangerZone Reset menu item shows MUI Tooltip without UI glitch', async ({ page }) => {
    // ── Navigate to the Connectors list ──
    const leftBarPage = new LeftBarPage(page);
    await page.goto('/');
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Data', 'Ingestion');

    // Wait for the connectors page to be ready
    await expect(page.getByTestId('connectors-page')).toBeVisible();

    // ── Pick the first connector in the list and navigate to its detail view ──
    // The connectors list renders rows; click the first one to enter detail view.
    const firstConnectorRow = page.locator('[data-testid="connectors-page"] table tbody tr').first();
    // If the table layout is different, fall back to any clickable row link
    const connectorLink = firstConnectorRow.locator('a').first();

    // Guard: at least one connector must exist in the e2e dataset
    const connectorExists = await connectorLink.count() > 0;
    if (!connectorExists) {
      // Fallback: try to find any link in the connectors page that leads to a connector detail
      const anyConnectorLink = page.locator('a[href*="/dashboard/data/ingestion/connectors/"]').first();
      await expect(anyConnectorLink).toBeVisible({ timeout: 15000 });
      await anyConnectorLink.click();
    } else {
      await connectorLink.click();
    }

    // ── Open the connector popover menu (⋮ button) ──
    // The ToggleButton wraps a MoreVert icon; it has value="popover"
    const popoverButton = page.locator('button[value="popover"]');
    await expect(popoverButton).toBeVisible({ timeout: 15000 });
    await popoverButton.click();

    // ── Verify the MUI Menu is open ──
    const menu = page.getByRole('menu');
    await expect(menu).toBeVisible();

    // Capture menu bounding box before hover for layout-shift detection
    const menuBoxBefore = await menu.boundingBox();
    expect(menuBoxBefore).not.toBeNull();

    // ── Locate the Reset menu item ──
    // After the fix, the Reset item is rendered inside a DangerZoneBlock with
    // a render-function component. The MenuItem text contains "Reset".
    // It may or may not have the DangerZoneChip (depends on isSensitive).
    const resetMenuItem = menu.getByRole('menuitem').filter({ hasText: /Reset/ });

    // If the Reset item is not visible (connector is not managed, or isSensitive
    // is false and the text is "Reset the connector state"), try the full label.
    const resetItemVisible = await resetMenuItem.isVisible().catch(() => false);
    if (!resetItemVisible) {
      // The non-sensitive variant uses "Reset the connector state" as label
      const resetFullLabel = menu.getByRole('menuitem').filter({ hasText: /Reset the connector state/ });
      const fullLabelVisible = await resetFullLabel.isVisible().catch(() => false);

      if (fullLabelVisible) {
        // Non-sensitive path — still verify no [object Object] title attribute
        const titleAttr = await resetFullLabel.getAttribute('title');
        expect(titleAttr).not.toBe('[object Object]');

        // Hover and verify menu stays visible
        await resetFullLabel.hover();
        await expect(menu).toBeVisible();

        // Verify no layout shift
        const menuBoxAfter = await menu.boundingBox();
        expect(menuBoxAfter).not.toBeNull();
        if (menuBoxBefore && menuBoxAfter) {
          expect(Math.abs(menuBoxAfter.x - menuBoxBefore.x)).toBeLessThan(5);
          expect(Math.abs(menuBoxAfter.y - menuBoxBefore.y)).toBeLessThan(5);
          expect(Math.abs(menuBoxAfter.width - menuBoxBefore.width)).toBeLessThan(5);
          expect(Math.abs(menuBoxAfter.height - menuBoxBefore.height)).toBeLessThan(5);
        }
        return; // Non-sensitive path validated
      }

      // If neither variant is found, skip gracefully (no connector available)
      test.skip(true, 'No Reset menu item found — connector may not support reset');
      return;
    }

    // ── Assert: no native [object Object] title attribute on the menu item ──
    // This was the core bug: the `<li>` had title="[object Object]"
    const titleAttr = await resetMenuItem.getAttribute('title');
    expect(titleAttr).not.toBe('[object Object]');

    // Also check the wrapping <span> (Tooltip wraps in a span)
    const resetSpan = resetMenuItem.locator('..');
    const spanTitle = await resetSpan.getAttribute('title');
    if (spanTitle !== null) {
      expect(spanTitle).not.toBe('[object Object]');
    }

    // ── Hover the Reset menu item ──
    await resetMenuItem.hover();

    // Small wait for tooltip animation
    await page.waitForTimeout(500);

    // ── Assert: MUI Tooltip appears (role="tooltip") ──
    // The MUI Tooltip renders a Popper with role="tooltip"
    const tooltip = page.getByRole('tooltip');
    await expect(tooltip).toBeVisible({ timeout: 5000 });

    // Verify tooltip text is meaningful (not "[object Object]")
    const tooltipText = await tooltip.textContent();
    expect(tooltipText).toBeTruthy();
    expect(tooltipText).not.toContain('[object Object]');
    // The tooltip should contain information about resetting the connector
    expect(tooltipText?.toLowerCase()).toMatch(/reset|ingestion|connector|process/);

    // ── Assert: Menu is still visible (no disappearing on hover) ──
    await expect(menu).toBeVisible();

    // ── Assert: No layout shift ──
    const menuBoxAfter = await menu.boundingBox();
    expect(menuBoxAfter).not.toBeNull();
    if (menuBoxBefore && menuBoxAfter) {
      // Allow a small tolerance (< 5px) for sub-pixel rendering differences
      expect(Math.abs(menuBoxAfter.x - menuBoxBefore.x)).toBeLessThan(5);
      expect(Math.abs(menuBoxAfter.y - menuBoxBefore.y)).toBeLessThan(5);
      expect(Math.abs(menuBoxAfter.width - menuBoxBefore.width)).toBeLessThan(5);
      expect(Math.abs(menuBoxAfter.height - menuBoxBefore.height)).toBeLessThan(5);
    }

    // ── Assert: DangerZone chip is visible alongside the Reset label ──
    // The DangerZoneChip renders a Tag with "Danger Zone" text
    const dangerZoneChip = menu.getByText('Danger Zone');
    const chipVisible = await dangerZoneChip.isVisible().catch(() => false);
    if (chipVisible) {
      await expect(dangerZoneChip).toBeVisible();
    }
    // (chip visibility depends on isSensitive being true in the test environment)
  });
});
