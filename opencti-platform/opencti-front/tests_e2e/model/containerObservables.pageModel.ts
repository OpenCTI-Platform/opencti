// eslint-disable-next-line import/no-extraneous-dependencies
import { Page } from '@playwright/test';

export default class ContainerObservablesPage {
  constructor(private page: Page) {
  }

  getContainerObservablesPage() {
    return this.page.getByTestId('container-observables-pages');
  }

  getObservableInContainer(observableName: string) {
    return this.page.getByRole('link', { name: observableName });
  }

  getAddObservableListButton() {
    return this.page.getByLabel('Add', { exact: true });
  }
}
