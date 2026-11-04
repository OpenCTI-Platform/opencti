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

  getLineCheckbox(index: number) {
    // The first checkbox of the table is the "Select all" one of the headers.
    return this.container.getByRole('checkbox').nth(index + 1);
  }

  async resizeColumn(index: number, deltaX: number) {
    const handle = this.container.locator('.react-draggable').nth(index);
    const box = await handle.boundingBox();
    if (!box) throw new Error(`No resize handle for column ${index}`);
    const x = box.x + box.width / 2;
    const y = box.y + box.height / 2;
    await this.page.mouse.move(x, y);
    await this.page.mouse.down();
    await this.page.mouse.move(x + deltaX, y, { steps: 10 });
    await this.page.mouse.up();
  }
}
