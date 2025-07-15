import { Page } from '@playwright/test';
import SDOTabs from "./SDOTabs.pageModel";

export default class IntrusionSetDetailsPage {
  tabs = new SDOTabs(this.page);

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
    return this.page.getByLabel('Add', { exact: true });
  }
}
