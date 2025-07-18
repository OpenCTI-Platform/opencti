import { Page } from '@playwright/test';
import LeftBarPage from './menu/leftBar.pageModel';

export default class NotesPage {
  pageUrl = '/dashboard/analyses/notes';
  constructor(private page: Page) {}

  /**
   * Reload the page (like F5), mostly used once on test start.
   * When possible please use navigateFromMenu instead it's faster.
   */
  async goto() {
    await this.page.goto(this.pageUrl);
  }

  async navigateFromMenu() {
    const leftBarPage = new LeftBarPage(this.page);
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Analyses', 'Notes');
  }

  getPage() {
    return this.page.getByTestId('notes-page');
  }

  addNew() {
    return this.getCreateNoteButton().click();
  }

  closeNew() {
    return this.page.getByLabel('Close', { exact: true }).click();
  }

  getCreateNoteButton() {
    return this.page.getByRole('button', { name: 'Create' });
  }

  getItemFromList(name: string) {
    return this.page.getByTestId(name).first();
  }
}
