import { Page } from '@playwright/test';

/**
 * Common page for all components in Overview tab.
 */
export default class SDOOverview {
  constructor(private page: Page) {}

  getAssignee(assignee: string) {
    return this.page.getByTestId('sdo-overview-assignees').getByLabel(assignee);
  }

  getLabel(label: string) {
    return this.page
      .getByRole('heading', { name: 'Labels' })
      .locator('..')
      .locator('..')
      .getByLabel(label);
  }

  getParticipant(participant: string) {
    return this.page.getByTestId('sdo-overview-participants').getByLabel(participant);
  }
}
