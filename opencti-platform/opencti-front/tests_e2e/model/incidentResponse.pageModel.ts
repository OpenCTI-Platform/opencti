import { Page } from '@playwright/test';

export default class IncidentResponsePage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('incident-page');
  }

  openNewIncidentResponseForm() {
    return this.page.getByRole('button', { name: 'Create' }).click();
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