import { Page } from '@playwright/test';

export class FiltersUtils {
  constructor(private page: Page) {
  }
  async addFilter(filterKey: string, filterLabel: string) {
    await this.page.getByLabel('Add filter').click();
    await this.page.getByRole('option', { name: filterKey }).click();
    await this.page.getByLabel(filterKey).click();
    await this.page.getByLabel(filterLabel).getByRole('checkbox').check();
    await this.page.locator('.MuiPopover-root > .MuiBackdrop-root').click();
  }
  
}
