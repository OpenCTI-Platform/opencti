
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
  getEditButton() {
    return this.page.getByLabel('Edit');
  }
}
