import { Page } from '@playwright/test';

export default class InvestigationPage {
  constructor(private page: Page) {}

  open() {
    return this.page.goto('/dashboard/workspaces/investigations');
  }

  openNewInvestigationForm() {
    return this.page.getByLabel('Add').click();
  }

  openUpdateOrDeleteInvestigationPopover(investigationName: string) {
    return this.page.locator('li').filter({ hasText: investigationName }).getByTestId('popover').click();
  }

  selectDeleteOptionFromInvestigationPopover() {
    return this.page.getByRole('menuitem', { name: 'Delete' }).click();
  }

  submitDeleteInvestigation() {
    return this.page.getByRole('button', { name: 'Delete' }).click();
  }
}
