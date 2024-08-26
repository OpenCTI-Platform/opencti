import { Page } from '@playwright/test';

export default class InvestigationsPage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('investigations-page');
  }

  addNewInvestigation() {
    return this.page.getByText('Create an investigation', { exact: true });
  }

  getCreateInvestigationButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  getItemFromList(name: string) {
    return this.page.getByText(name, { exact: true });
  }
}
