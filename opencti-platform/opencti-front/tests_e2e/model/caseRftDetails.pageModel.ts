import { Page } from '@playwright/test';
import SDOTabs from './SDOTabs.pageModel';

export default class CaseRftDetailsPage {
  tabs: SDOTabs;

  constructor(private page: Page) {
    this.tabs = new SDOTabs(this.page);
  }

  getPage() {
    return this.page.getByTestId('case-rft-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getAddParticipantsButton() {
    return this.page.getByRole('button', { name: 'Add new participants' });
  }

  getParticipant(name: string) {
    return this.page.getByRole('button', { name });
  }

  getUpdateButton() {
    return this.page.getByRole('button', { name: 'Update', exact: true });
  }
}
