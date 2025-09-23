import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class IncidentResponsePage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('incident-response-page');
  }

  openNewIncidentResponseForm() {
    return this.page.getByRole('button', { name: 'Create' }).click();
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Cases', 'Incident responses');
  }

  closeNewIncidentResponse() {
    return this.page.getByLabel('Close', { exact: true }).click();
  }

  getIncidentResponseNameInput() {
    return this.page.getByLabel('Name');
  }

  getCreateIncidentResponseButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }

  checkItemInList(name: string) {
    return this.getItemFromList(name).getByRole('checkbox').click();
  }
}
