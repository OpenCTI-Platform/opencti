import { Page } from '@playwright/test';
import { expect } from '../../fixtures/baseFixtures';

/**
 * Wraps the draft toolbar (`DraftToolbar.tsx`, `data-testid="draft-toolbar"`): current workflow
 * status (`WorkflowStatus.tsx`), available transitions (`WorkflowTransitions.tsx`) and their
 * single combined wizard dialog (comment/organizations/validation, `useTransitionWizard.ts`).
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
   * Clicks a transition by its exact event name. Handles both UI variants: a direct button
   * (exactly 1 allowed transition) and the "Next status" dropdown menu (2 or more, per
   * `WorkflowTransitions.tsx`'s `allowedTransitions.length > 1` check).
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

  /**
   * Asserts a transition is available without triggering it. Same two UI variants as
   * `openTransition`: a visible direct button, or a menu item inside the (closed) "Next
   * status" dropdown - opened, checked, then closed again to leave the toolbar as found.
   */
  async assertTransitionVisible(eventName: string) {
    const actions = this.getTransitionsActions();
    const directButton = actions.getByRole('button', { name: eventName, exact: true });
    const nextStatusButton = actions.getByRole('button', { name: 'Next status' });
    await expect(directButton.or(nextStatusButton)).toBeVisible();
    if (await directButton.count() > 0) {
      return;
    }
    await nextStatusButton.click();
    await expect(this.page.getByRole('menuitem', { name: eventName, exact: true })).toBeVisible();
    await this.page.keyboard.press('Escape');
  }

  /**
   * Fills whatever fields the current transition's wizard dialog shows - comment, share/unshare
   * organizations - and submits in one go: `WorkflowTransitions.tsx` renders them together in a
   * single Formik form rather than the sequential org-picker/comment/validate dialogs of before.
   * `cancel` clicks "Cancel" instead of submitting.
   */
  async fillWizard({ share = [], unshare = [], comment, cancel = false }: {
    share?: string[];
    unshare?: string[];
    comment?: string;
    cancel?: boolean;
  } = {}) {
    if (cancel) {
      return this.page.getByRole('button', { name: 'Cancel' }).click();
    }
    for (const orgName of share) {
      await this.page.getByLabel('Organizations to share with').click();
      await this.page.getByRole('option', { name: orgName, exact: true }).click();
    }
    for (const orgName of unshare) {
      await this.page.getByLabel('Organizations to unshare from').click();
      await this.page.getByRole('option', { name: orgName, exact: true }).click();
    }
    if (comment) {
      // getByRole('textbox', ...) instead of getByLabel: the wizard dialog's title ("Add a
      // comment") is wired via aria-labelledby onto the dialog root, so a getByLabel('Comment')
      // substring match also matches the dialog itself, not just the TextField. Scoping to the
      // 'textbox' role excludes the dialog. (Not `exact: true` - a required comment's label gets
      // a trailing " *" from the design system, which a substring match on 'Comment' still needs
      // to catch.)
      await this.page.getByRole('textbox', { name: 'Comment' }).fill(comment);
    }
    return this.getWizardSubmitButton().click();
  }

  /** The dialog's single submit button - labeled "Approve" for a validating transition, "Confirm" otherwise. */
  getWizardSubmitButton() {
    return this.page.getByRole('button', { name: 'Confirm' }).or(this.page.getByRole('button', { name: 'Approve' }));
  }

  /** With a required comment left empty, the submit button is disabled (`WorkflowTransitions.tsx`). */
  async assertCommentConfirmDisabled() {
    await expect(this.getWizardSubmitButton()).toBeDisabled();
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

  private getLastCommentDialog() {
    return this.page.getByRole('dialog').filter({
      has: this.page.getByRole('heading', { name: 'Last workflow comment', exact: true }),
    });
  }

  async assertLastCommentVisible(text: string) {
    // `useDraftCommentPopup` auto-opens a "Last workflow comment" dialog the first time this
    // browser (localStorage is keyed by draftId only, not per-user) sees a given comment. It can
    // pop up at any point (e.g. on the toolbar's periodic background refetch) including mid-click,
    // so this dismisses it in a retrying loop instead of a single point-in-time check, until the
    // toolbar button click actually goes through.
    const commentDialog = this.getLastCommentDialog();
    await expect(async () => {
      if (await commentDialog.isVisible()) {
        await commentDialog.getByRole('button', { name: 'Close' }).click();
        await expect(commentDialog).toBeHidden();
      }
      await this.getToolbar().getByLabel('View last comment').click({ timeout: 2000 });
    }).toPass({ timeout: 30000 });
    await expect(this.page.getByText(text)).toBeVisible();
  }

  /** Exits without an associated container entity navigates to the drafts list
   * (`DraftExit.tsx`'s `onCompleted` fallback) - wait for it to actually load. */
  async exitDraft() {
    // The unseen-comment modal (`useDraftCommentPopup`) can (re)open at any point, including after
    // the "Exit draft" click - e.g. the toolbar's periodic background refetch surfaces a comment
    // from another persona's transition made while this one was on the page. A single dismiss
    // isn't enough, so this retries dismiss-then-click as a unit, like `assertLastCommentVisible`,
    // instead of relying on `addLocatorHandler` (whose own dismiss click can stall indefinitely if
    // the dialog reopens mid-click).
    const commentDialog = this.getLastCommentDialog();
    await expect(async () => {
      if (await commentDialog.isVisible()) {
        await commentDialog.getByRole('button', { name: 'Close', exact: true }).click();
        await expect(commentDialog).toBeHidden();
      }
      await this.getToolbar().getByRole('button', { name: 'Exit draft' }).click({ timeout: 2000 });
    }).toPass({ timeout: 30000 });
    await expect(this.page.getByTestId('draft-page')).toBeVisible();
  }

  /** Check the authenticated navigation's draft context instead of treating a slow toolbar as absent. */
  async exitDraftIfPresent() {
    await expect(this.page.getByLabel('Main navigation', { exact: true })).toBeVisible();
    if (await this.page.getByRole('link', { name: 'Draft overview', exact: true, includeHidden: true }).isVisible()) {
      await this.exitDraft();
    }
  }
}
