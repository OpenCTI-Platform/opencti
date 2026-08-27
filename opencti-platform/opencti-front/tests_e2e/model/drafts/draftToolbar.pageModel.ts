import { Page } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';

/**
 * Wraps the draft toolbar (`DraftToolbar.tsx`, `data-testid="draft-toolbar"`): current workflow
 * status (`WorkflowStatus.tsx`), available transitions (`WorkflowTransitions.tsx`) and their
 * org-picker/comment/validate wizard dialogs (`useTransitionWizard.ts`).
 */
export default class DraftToolbarPageModel {
  constructor(private readonly page: Page) {
  }

  getToolbar() {
    return this.page.getByTestId('draft-toolbar');
  }

  /** A user with no access at all to the draft gets `ErrorNotFound` instead of the toolbar. */
  getNoAccessMessage() {
    return this.page.getByText('This page is not found on this OpenCTI application.');
  }

  async assertNoAccess() {
    await expect(this.getNoAccessMessage()).toBeVisible();
  }

  async assertHasAccess() {
    await expect(this.getToolbar()).toBeVisible();
  }

  async assertStatus(statusName: string) {
    await expect(this.getToolbar().getByText(statusName, { exact: true })).toBeVisible();
  }

  getTransitionsActions() {
    return this.getToolbar().getByTestId('workflow-transitions-actions');
  }

  /** Asserts the draft is view-only: accessible, but no transition buttons/menu are shown. */
  async assertNoTransitions() {
    await this.assertHasAccess();
    await expect(this.getTransitionsActions()).toHaveCount(0);
  }

  /**
   * Clicks a transition by its exact event name. Handles both UI variants: direct buttons
   * (< 3 allowed transitions) and the "Next status" dropdown menu (>= 3 allowed transitions).
   */
  async openTransition(eventName: string) {
    const actions = this.getTransitionsActions();
    const directButton = actions.getByRole('button', { name: eventName, exact: true });
    const nextStatusButton = actions.getByRole('button', { name: 'Next status' });
    // The toolbar's transitions are fetched asynchronously - wait for either variant to render
    // instead of an immediate (and possibly premature) count() check.
    await expect(directButton.or(nextStatusButton)).toBeVisible();
    if (await directButton.count() > 0) {
      return directButton.click();
    }
    await nextStatusButton.click();
    return this.page.getByRole('menuitem', { name: eventName, exact: true }).click();
  }

  /** Step 1 of the wizard (only shown for transitions with `requiresShareOrganizationInput`/`requiresUnshareOrganizationInput`). */
  async fillOrgPickerStep({ share = [], unshare = [] }: { share?: string[]; unshare?: string[] }) {
    for (const orgName of share) {
      await this.page.getByLabel('Organizations to share with').click();
      await this.page.getByRole('option', { name: orgName, exact: true }).click();
    }
    for (const orgName of unshare) {
      await this.page.getByLabel('Organizations to unshare from').click();
      await this.page.getByRole('option', { name: orgName, exact: true }).click();
    }
    return this.page.getByRole('button', { name: 'Confirm' }).click();
  }

  /** Step 2 of the wizard (comment, required for "Reject" transitions). */
  async fillCommentStep({ comment, cancel = false }: { comment?: string; cancel?: boolean }) {
    if (cancel) {
      return this.page.getByRole('button', { name: 'Cancel' }).click();
    }
    if (comment) {
      await this.page.getByLabel('Comment').fill(comment);
    }
    return this.page.getByRole('button', { name: 'Confirm' }).click();
  }

  getCommentConfirmButton() {
    return this.page.getByRole('button', { name: 'Confirm' });
  }

  /** With a required comment left empty, the Confirm button is disabled (`WorkflowTransitions.tsx`). */
  async assertCommentConfirmDisabled() {
    await expect(this.getCommentConfirmButton()).toBeDisabled();
  }

  /** Step 3 of the wizard ("Validate" transition - approves the draft and exits draft mode). */
  confirmValidateDraft() {
    return this.page.getByRole('button', { name: 'Approve' }).click();
  }

  /** Force-unlock button shown on pending/error transitions (bypass users only) - "Clear" just orphans the background task and re-enables the transition, there is no "Retry". */
  getClearButton() {
    return this.getToolbar().getByRole('button', { name: 'Clear' });
  }

  async assertTransitionError() {
    await expect(this.getToolbar().getByTestId('workflow-transitions-error')).toBeVisible();
  }

  async assertTransitionPending() {
    await expect(this.getToolbar().getByTestId('workflow-transitions-pending')).toBeVisible();
  }

  async assertLastCommentVisible(text: string) {
    await this.getToolbar().getByLabel('View last comment').click();
    await expect(this.page.getByText(text)).toBeVisible();
  }

  /** Exits without an associated container entity navigates to the drafts list
   * (`DraftExit.tsx`'s `onCompleted` fallback) - wait for it to actually load. */
  async exitDraft() {
    await this.getToolbar().getByRole('button', { name: 'Exit draft' }).click();
    await expect(this.page.getByTestId('draft-page')).toBeVisible({ timeout: 5000 });
  }

  /** A previous, interrupted test run can leave a user stuck in a draft context; call after login and before navigating elsewhere. Uses a bounded wait since the toolbar mounts asynchronously. */
  async exitDraftIfPresent() {
    const isPresent = await this.getToolbar().waitFor({ state: 'visible', timeout: 5000 }).then(() => true).catch(() => false);
    if (isPresent) {
      await this.exitDraft();
    }
  }
}
