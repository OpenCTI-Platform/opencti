import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class InfrastructureDetailsPageModel {
  tabs = new SDOTabs(this.page);
  constructor(private page: Page) {}

  getInfrastructureDetailsPage() {
    return this.page.getByTestId('infrastructure-details-page');
  }

  getPage() {
    return this.page.getByTestId('infrastructure-overview');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getKnowledgeTab() {
    return this.page.getByRole('tab', { name: 'Knowledge' }).click();
  }

  getVictimologyTab() {
    return this.page.getByRole('menuitem', { name: 'Victimology' }).click();
  }

  getCreateRelationshipButton() {
    return this.page.getByRole('button', { name: 'Create Relationship' });
  }
}
