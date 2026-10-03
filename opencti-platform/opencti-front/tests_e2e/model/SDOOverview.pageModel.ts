import { Page } from '@playwright/test';

/**
 * Common page for all components in Overview tab.
 */

// The library Chip body is a plain span: no role, no accessible name. Only its
// delete control is named (`Remove <value>`), so getByLabel cannot see the chip
// at all -- it matched the delete button by substring, which is what the old
// bare-value locator was really hitting. Match the visible TEXT instead, and
// anchor it so `admin` does not also match `Remove admin`. The chip renders the
// value through three nested spans; Playwright's text engine binds to the one
// that owns the text node, so this stays a single element.
const wholeLabel = (value: string) => new RegExp(`^${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i');

export default class SDOOverview {
  constructor(private page: Page) {}

  getAssignee(assignee: string) {
    return this.page.getByTestId('sdo-overview-assignees').getByText(wholeLabel(assignee));
  }

  getLabel(label: string) {
    return this.page
      .getByText('Labels')
      .locator('..')
      .locator('..')
      .getByText(wholeLabel(label));
  }

  getParticipant(participant: string) {
    return this.page.getByTestId('sdo-overview-participants').getByText(wholeLabel(participant));
  }
}
