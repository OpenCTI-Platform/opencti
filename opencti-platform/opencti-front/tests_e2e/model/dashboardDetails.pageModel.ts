
import { Page } from "@playwright/test";

export class DashboardDetailsPage {
  constructor(private page: Page) {
  }
  getDashboardDetailsPage() {
    return this.page.getByTestId('dashboard-details-page');
  }
  getTitle(name: string){
    return this.page.getByRole('heading',{name});
  }
  openPopUpButton() {
    return this.page.getByTestId('popover');
  }
  getEditButton() {
    return this.page.getByRole('menuitem', { name: 'Update' });
  }
  addNewDashboardTag() {
    return this.page.getByLabel('Add tag', { exact: true })
  }
  getTag(name: string) {
    return this.page.getByRole('button', {name});
  }
}
