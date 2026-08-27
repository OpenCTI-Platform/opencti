import { Page } from '@playwright/test';
import SettingsCustomizationPage from '../settingsCustomization.pageModel';

/**
 * Wraps the react-flow based workflow graph editor (`Workflow.tsx`,
 * Settings > Customization > Entity types > Draft > Workflow tab).
 *
 * Node lookup strategy: nodes are located by their visible label text within the generic
 * `.react-flow__node` wrapper rather than by their underlying id (a server-generated
 * StatusTemplate uuid we don't know ahead of time from the UI). This works because status/
 * transition/placeholder node ids are all unique per visible label at any point during
 * construction (newly-created, not-yet-renamed transitions always show as "New event").
 */
export default class WorkflowEditorPageModel {
  constructor(private readonly page: Page) {
  }

  /** Navigate to the Workflow tab of the "Draft" entity type in Settings > Customization. */
  async goto() {
    const settingsCustomization = new SettingsCustomizationPage(this.page);
    await settingsCustomization.navigateFromMenu();
    await settingsCustomization.getItemFromList('Draft').click();
    return this.page.getByRole('tab', { name: 'Workflow' }).click();
  }

  /** Reload the page - used to force a fresh `initialState` from the server (see repo memory). */
  reload() {
    return this.page.reload();
  }

  clickAddStatus() {
    return this.page.getByRole('button', { name: 'Add Status' }).click();
  }

  async clearWorkflow() {
    await this.page.getByRole('button', { name: 'Add Status' }).waitFor({ state: 'visible' });
    const hasExistingNodes = (await this.page.locator('.react-flow__node').count()) > 0;
    if (!hasExistingNodes) {
      return;
    }
    await this.page.getByTestId('workflow-publish-dropdown-toggle').click();
    await this.page.getByTestId('workflow-reset-menu-item').click();
    await this.page.getByTestId('workflow-reset-confirm-button').click();
    await this.page.locator('.react-flow__node').first().waitFor({ state: 'detached' });
  }

  /** Locates a status/transition node by its exact visible label (avoids substring false-positives, e.g. "New" vs "New event"). */
  getNodeByLabel(label: string) {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return this.page.locator('.react-flow__node').filter({ hasText: new RegExp(`^${escaped}$`) });
  }

  clickNodeByLabel(label: string) {
    return this.getNodeByLabel(label).click();
  }

  /** The single "+" placeholder currently attached to whichever status has no outgoing edge yet. */
  getPlaceholderNode() {
    return this.page.getByTestId(/^workflow-placeholder-node-/);
  }

  clickPlaceholder() {
    return this.getPlaceholderNode().click();
  }

  /** A freshly-created, not-yet-renamed transition node (default event name "NEW_EVENT"). */
  getNewTransitionNode() {
    return this.getNodeByLabel('New event');
  }

  clickNewTransitionNode() {
    return this.getNewTransitionNode().click();
  }

  /**
   * `useWorkflowLayout`'s auto-layout + the graph's `fitView()` effect both re-run on every
   * nodes/edges change (e.g. right after the previous drawer submit), which can still be
   * repositioning nodes for a couple of render cycles after the action that triggered it
   * resolves. Polls a handle's bounding box until two consecutive reads agree, so a drag started
   * right after such a change doesn't aim at an already-stale coordinate.
   */
  private async getStableBoundingBox(locator: ReturnType<Page['locator']>) {
    let previous = await locator.boundingBox();
    for (let i = 0; i < 10; i += 1) {
      await this.page.waitForTimeout(100);
      const current = await locator.boundingBox();
      if (previous && current && previous.x === current.x && previous.y === current.y) {
        return current;
      }
      previous = current;
    }
    return previous;
  }

  /**
   * Drags a connection from one existing status node to another, triggering
   * `useStatusConnection`'s Status->Status handler which auto-creates the linking transition
   * node (default name "NEW_EVENT") and both edges. Needed only when the source status already
   * has an outgoing edge (so no "+" placeholder is available to use instead).
   */
  async dragConnectStatuses(sourceStatusLabel: string, targetStatusLabel: string) {
    const sourceHandle = this.getNodeByLabel(sourceStatusLabel).locator('.react-flow__handle-bottom');
    const targetHandle = this.getNodeByLabel(targetStatusLabel).locator('.react-flow__handle-top');
    const sourceBox = await this.getStableBoundingBox(sourceHandle);
    const targetBox = await this.getStableBoundingBox(targetHandle);
    if (!sourceBox || !targetBox) {
      throw new Error(`Could not locate connection handles between "${sourceStatusLabel}" and "${targetStatusLabel}"`);
    }
    const sourcePoint = { x: sourceBox.x + sourceBox.width / 2, y: sourceBox.y + sourceBox.height / 2 };
    const targetPoint = { x: targetBox.x + targetBox.width / 2, y: targetBox.y + targetBox.height / 2 };
    await this.page.mouse.move(sourcePoint.x, sourcePoint.y);
    await this.page.mouse.down();
    await this.page.mouse.move(targetPoint.x, targetPoint.y, { steps: 15 });
    await this.page.mouse.up();
  }

  getPublishButton() {
    return this.page.getByTestId('workflow-publish-button');
  }

  publish() {
    return this.getPublishButton().click();
  }
}
