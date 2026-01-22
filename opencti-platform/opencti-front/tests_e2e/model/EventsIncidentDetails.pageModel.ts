import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class EventsIncidentDetailsPage {
  tabs = new SDOTabs(this.page);

  constructor(private page: Page) {}

  getPage() {
    return this.page.getByTestId('incident-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getIncidentDetailsPage() {
    return this.page.getByTestId('incident-details-page');
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
