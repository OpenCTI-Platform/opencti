import { Page } from '@playwright/test';

export default class DataTablePage {
  container = this.page.locator('.datatable-container').first();

  constructor(private page: Page) {}

  getNumberElements(nbElements: number) {
    return this.page.getByText(`/ ${nbElements}`, { exact: true });
  }

  getCheckAll() {
    return this.page.getByTestId('dataTableCheckAll').getByRole('checkbox');
  }
}
