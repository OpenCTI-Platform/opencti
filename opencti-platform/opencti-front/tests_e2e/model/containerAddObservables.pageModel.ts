import { Page } from '@playwright/test';

export default class ContainerAddObservablesPage {
  constructor(private page: Page) {
  }

  getAddNewObservableButton() {
    return this.page.getByRole('button', { name: 'Create an observable', exact: true });
  }

  getIPV4ButtonInNewObservable() {
    return this.page.getByRole('button', { name: 'IPV4 address' });
  }

  getNewIPV4ValueInput() {
    return this.page.getByLabel('value');
  }

  async fillNewIPV4ValueInput(ipv4Value: string) {
    await this.getNewIPV4ValueInput().click();
    return this.getNewIPV4ValueInput().fill(ipv4Value);
  }

  getNewObservableCreateButton() {
    return this.page.getByRole('button', { name: 'Create', exact: true });
  }

  async createNewIPV4Observable(ipv4Value: string) {
    await this.getAddNewObservableButton().click();
    await this.getIPV4ButtonInNewObservable().click();
    await this.fillNewIPV4ValueInput(ipv4Value);
    return this.getNewObservableCreateButton().click();
  }

  getObservable(observableName: string) {
    return this.page.getByRole('button', { name: observableName });
  }

  getCloseObservablesListButton() {
    return this.page.getByRole('button', { name: 'Close' });
  }
}
