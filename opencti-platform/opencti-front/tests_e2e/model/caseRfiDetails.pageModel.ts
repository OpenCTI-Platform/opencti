import { Page } from '@playwright/test';

export default class CaseRfiDetailsPage {
  constructor(private page: Page) {}

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
