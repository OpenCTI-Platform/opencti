import { Page } from '@playwright/test';

export default class InvestigationDetailsPage {
  constructor(private page: Page) {
  }

  getInvestigationDetailsPage() {
    return this.page.getByTestId('investigation-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  openPopUpButton() {
    return this.page.getByLabel('Workspace popover of actions');
  }

  getEditButton() {
    return this.page.getByRole('menuitem', { name: 'Update' });
  }

  getDeleteButton() {
    return this.page.getByRole('menuitem', { name: 'Delete' });
  }

  getConfirmButton() {
    return this.page.getByRole('button', { name: 'Confirm' });
  }

  addNewInvestigationTag() {
    return this.page.getByLabel('Add tag');
  }

  getTag(name: string) {
    return this.page.getByRole('button', { name });
  }
}
