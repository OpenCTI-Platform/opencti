import { Page } from '@playwright/test';

/**
 * Common page for all components in Overview tab.
 */

// A chip's accessible name is the value itself; its delete control is named
// `Remove <value>`. getByLabel matches substrings, so a bare value matches both
// and Playwright reports a strict mode violation. Anchoring the match keeps the
// chip and excludes the delete button, without weakening either label.
const wholeLabel = (value: string) => new RegExp(`^${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i');

export default class SDOOverview {
  constructor(private page: Page) {}

  getAssignee(assignee: string) {
    return this.page.getByTestId('sdo-overview-assignees').getByLabel(wholeLabel(assignee));
  }

  getLabel(label: string) {
    return this.page
      .getByText('Labels')
      .locator('..')
      .locator('..')
      .getByLabel(wholeLabel(label));
  }

  getParticipant(participant: string) {
    return this.page.getByTestId('sdo-overview-participants').getByLabel(wholeLabel(participant));
  }
}
