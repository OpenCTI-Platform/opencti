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
    return this.page.getByRole('textbox', { name: 'value' });
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

  getPanel() {
    return this.page.getByRole('dialog', { name: 'Add observables' });
  }

  // Scoped to the panel: the success message has a Close button too
  getCloseObservablesListButton() {
    return this.getPanel().getByRole('button', { name: 'Close' });
  }

  // The message locators include hidden elements: while the panel (a modal drawer) is open,
  // MUI sets aria-hidden on the rest of the app, the message included.

  // Any message: its text is checked by the caller
  getMessage() {
    return this.page.getByRole('alert', { includeHidden: true });
  }

  // The confirmation shown once a created object is added to the container
  getAddedMessage() {
    return this.page.getByRole('status', { includeHidden: true });
  }

  getUndoButton() {
    return this.getMessage().getByRole('button', { name: 'Undo', exact: true, includeHidden: true });
  }

  getCloseMessageButton() {
    return this.getMessage().getByRole('button', { name: 'Close', exact: true, includeHidden: true });
  }
}
