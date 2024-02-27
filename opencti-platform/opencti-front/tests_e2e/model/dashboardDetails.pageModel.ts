// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';

export default class DashboardDetailsPage {
  constructor(private page: Page) {
  }

  getDashboardDetailsPage() {
    return this.page.getByTestId('dashboard-details-page');
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

  addNewDashboardTag() {
    return this.page.getByLabel('Add tag', { exact: true });
  }

  getTag(name: string) {
    return this.page.getByRole('button', { name });
  }
}
