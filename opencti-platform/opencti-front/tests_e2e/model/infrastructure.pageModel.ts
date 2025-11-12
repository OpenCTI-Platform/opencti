import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class InfrastructurePage {
  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('infrastructures-page');
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Observations', 'Infrastructures');
  }

  addNewInfrastructure() {
    return this.page.getByLabel('Create Infrastructure', { exact: true }).click();
  }

  getCreateInfrastructureButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name);
  }
}
