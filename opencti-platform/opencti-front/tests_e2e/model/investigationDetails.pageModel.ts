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
    return this.page.getByTestId('popover');
  }

  getEditButton() {
    return this.page.getByRole('menuitem', { name: 'Update' });
  }

  getDeleteButton() {
    return this.page.getByRole('menuitem', { name: 'Delete' });
  }

  getDelete() {
    return this.page.getByRole('button', { name: 'Delete' });
  }

  addNewInvestigationTag() {
    return this.page.getByLabel('Add tag');
  }

  getTag(name: string) {
    return this.page.getByRole('button', { name });
  }
}
