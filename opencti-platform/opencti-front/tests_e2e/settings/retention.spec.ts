import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import RetentionPage from '../model/retention.pageModel';

/**
 * Content of the test
 * -------------------
 * Golden path for Retention Policies feature:
 * 1. Navigate to Settings > Customization > Retention.
 * 2. Create a new knowledge-scope retention policy.
 * 3. Verify the policy appears in the list with correct data.
 * 4. Update the retention policy via the popover menu.
 * 5. Deactivate then reactivate the policy via the popover menu.
 * 6. Delete the policy via the popover menu and confirm deletion.
 */
test('Retention policy CRUD', { tag: ['@ce'] }, async ({ page }) => {
  const retentionPage = new RetentionPage(page);
  const retentionName = `Test Retention - ${uuid()}`;

  // ─── Navigate ────────────────────────────────────────────────────────────────
  await retentionPage.goto();
  await expect(retentionPage.getPage()).toBeVisible();

  // ─── Open creation form ───────────────────────────────────────────────────────
  await retentionPage.getCreateButton().click();
  await expect(page.getByText('Create a retention policy')).toBeVisible();

  // ─── Verify form validation ───────────────────────────────────────────────────
  // The Create button should be disabled before Verify is called
  await expect(retentionPage.getCreateFormButton()).toBeDisabled();

  // Fill in the name field
  await page.getByRole('textbox', { name: 'Name' }).fill(retentionName);

  // Fill max_retention
  await page.getByRole('textbox', { name: 'Maximum retention' }).fill('90');

  // ─── Click Verify (required to enable the Create button) ─────────────────────
  await retentionPage.getVerifyButton().click();

  // Wait for the Create button to become enabled after Verify completes
  await expect(retentionPage.getCreateFormButton()).toBeEnabled({ timeout: 15000 });

  // ─── Create the retention policy ─────────────────────────────────────────────
  await retentionPage.getCreateFormButton().click();

  // ─── Verify the rule appears in the list ────────────────────────────────────
  const retentionItem = retentionPage.getItemFromList(retentionName);
  await expect(retentionItem).toBeVisible();

  // Verify it shows "Active" status
  await expect(retentionItem.getByText('Active')).toBeVisible();

  // Verify the retention unit is visible (days by default)
  await expect(retentionItem.getByText(/90/)).toBeVisible();

  // ─── Open popover and test Deactivate ────────────────────────────────────────
  await retentionPage.getPopoverButton(retentionItem).click();
  await expect(retentionPage.getDeactivateMenuItem()).toBeVisible();
  await retentionPage.getDeactivateMenuItem().click();

  // Verify the status changed to "Inactive"
  await expect(retentionItem.getByText('Inactive')).toBeVisible();

  // ─── Open popover and test Activate ──────────────────────────────────────────
  await retentionPage.getPopoverButton(retentionItem).click();
  await expect(retentionPage.getActivateMenuItem()).toBeVisible();
  await retentionPage.getActivateMenuItem().click();

  // Verify the status is back to "Active"
  await expect(retentionItem.getByText('Active')).toBeVisible();

  // ─── Open popover and test Update ────────────────────────────────────────────
  await retentionPage.getPopoverButton(retentionItem).click();
  await retentionPage.getUpdateMenuItem().click();

  // Verify the edition drawer opens
  await expect(page.getByText('Update a retention policy')).toBeVisible();

  // Update the name and max_retention
  const updatedName = `${retentionName} Updated`;
  const nameInput = page.getByRole('textbox', { name: 'Name' });
  await nameInput.fill(updatedName);
  await page.getByRole('textbox', { name: 'Maximum retention' }).fill('60');

  // Submit the update
  await retentionPage.getDrawerUpdateButton().click();

  // ─── Verify the updated rule is in the list ──────────────────────────────────
  const updatedRetentionItem = retentionPage.getItemFromList(updatedName);
  await expect(updatedRetentionItem).toBeVisible();
  await expect(updatedRetentionItem.getByText(/60/)).toBeVisible();

  // ─── Open popover and test Delete ────────────────────────────────────────────
  await retentionPage.getPopoverButton(updatedRetentionItem).click();
  await retentionPage.getDeleteMenuItem().click();

  // Verify the confirmation dialog appears
  await expect(page.getByText('Do you want to delete this retention policy?')).toBeVisible();

  // Cancel first to verify the rule is still there
  await retentionPage.getCancelDialogButton().click();
  await expect(updatedRetentionItem).toBeVisible();

  // Delete for real
  await retentionPage.getPopoverButton(updatedRetentionItem).click();
  await retentionPage.getDeleteMenuItem().click();
  await retentionPage.getConfirmButton().click();

  // Verify the rule is gone from the list
  await expect(retentionPage.getItemFromList(updatedName)).not.toBeVisible();
});

