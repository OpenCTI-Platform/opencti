import { Page } from '@playwright/test';

export default class IntrusionSetDetailsPage {
  constructor(private page: Page) {}

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
    return this.page.getByRole('menuitem', { name: 'Victimology' }).click();
  }

  getCreateRelationshipButton() {
    return this.page.getByRole('button', { name: 'Create Relationship' });
  }
}
