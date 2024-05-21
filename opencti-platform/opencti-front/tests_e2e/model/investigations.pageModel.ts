import { Page } from '@playwright/test';

export default class InvestigationsPage {
  constructor(private page: Page) {
  }

  getPage() {
    return this.page.getByTestId('investigations-page');
  }

  openButtonModal() {
    return this.page.getByLabel('Create', { exact: true });
  }

  addNewInvestigation() {
    return this.page.getByText('Create an investigation', { exact: true });
  }

  getInvestigationNameInput() {
    return this.page.getByLabel('Name');
  }

  getCreateInvestigationButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  getItemFromList(name: string) {
    return this.page.getByRole('link', { name }).first();
  }
}
