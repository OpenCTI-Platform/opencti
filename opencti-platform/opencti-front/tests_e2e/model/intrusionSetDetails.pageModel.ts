import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class IntrusionSetDetailsPage {
  tabs: SDOTabs;

  constructor(private page: Page) {
    this.tabs = new SDOTabs(this.page);
  }

  getIntrusionSetDetailsPage() {
    return this.page.getByTestId('intrusionSet-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getKnowledgeTab() {
    return this.page.getByRole('tab', { name: 'Knowledge' }).click();
  }

  getVictimologyTab() {
    // The knowledge bar's rows are real links now, not MUI menu items: the bar
    // is permanent navigation, not an application menu with roving focus.
    return this.page.getByRole('link', { name: 'Victimology' }).click();
  }

  getCreateRelationshipButton() {
    return this.page.getByRole('button', { name: 'Create Relationship' });
  }
}
