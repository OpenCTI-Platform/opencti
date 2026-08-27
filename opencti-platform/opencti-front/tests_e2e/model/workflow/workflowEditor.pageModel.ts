import { Page } from '@playwright/test';
import SettingsCustomizationPage from '../settingsCustomization.pageModel';

/**
 * Wraps the react-flow based workflow graph editor (`Workflow.tsx`,
 * Settings > Customization > Entity types > Draft > Workflow tab).
 *
 * Nodes are located by their visible label text within the generic `.react-flow__node` wrapper
 * rather than by their server-generated StatusTemplate id, which we don't know ahead of time.
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

  /** Polls a handle's bounding box until two consecutive reads agree, so a drag doesn't aim at a still-repositioning node right after a layout change. */
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

  /** Drags a connection from one status node to another, auto-creating the linking transition node. Needed only when the source status already has an outgoing edge (no "+" placeholder available). */
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
