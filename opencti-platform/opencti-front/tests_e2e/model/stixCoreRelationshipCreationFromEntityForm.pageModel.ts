import { Page } from '@playwright/test';

export default class StixCoreRelationshipCreationFromEntityFormPage {
  constructor(private page: Page) {}

  getStixCoreRelationshipCreationFromEntityComponent() {
    return this.page.getByTestId('stixCoreRelationshipCreationFromEntity-component');
  }
}
