import { Locator, Page } from '@playwright/test';

export default class DataTablePage {
  container: Locator;

  constructor(private page: Page) {
    this.container = this.page.locator('.datatable-container').first();
  }

  getNumberElements(nbElements: number) {
    return this.page.getByText(`/ ${nbElements}`, { exact: true });
  }

  getCheckAll() {
    return this.page.getByTestId('dataTableCheckAll').getByRole('checkbox');
  }
}
