import { Page } from '@playwright/test';
import { expect } from '../fixtures/baseFixtures';
import AutocompleteFieldPageModel from './field/AutocompleteField.pageModel';
import SDOTabs from './SDOTabs.pageModel';
import SDOOverview from './SDOOverview.pageModel';
import CardPage from './card.pageModel';

export default class ReportDetailsPage {
  labelsSelect: AutocompleteFieldPageModel;
  tabs: SDOTabs;
  overview: SDOOverview;
  card: CardPage;

  constructor(private page: Page) {
    this.labelsSelect = new AutocompleteFieldPageModel(this.page, 'Labels', true);
    this.tabs = new SDOTabs(this.page);
    this.overview = new SDOOverview(this.page);
    this.card = new CardPage(this.page);
  }

  getPage() {
    return this.page.getByTestId('report-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getEditButton() {
    return this.page.getByLabel('Update', { exact: true });
  }

  getAiInsightsButton() {
    return this.page.getByRole('button', { name: 'AI Insights', exact: true });
  }

  getContentFile(fileName: string) {
    return this.page.getByLabel(fileName);
  }

  getTextForHeading(heading: string, text: string) {
    // exact: false substring matching would also match e.g. "Reliability (of author)" for "Author".
    return this.page
      .getByRole('heading', { name: heading, exact: true })
      .locator('../..')
      .getByText(text);
  }

  getTextForCard(cardTitle: string, text: string) {
    return this.card.getTextInCard(cardTitle, text);
  }

  openLabelsSelect() {
    return this.page.getByLabel('Add new labels').click();
  }

  addLabels() {
    return this.page.getByText('Add', { exact: true }).click();
  }

  getExportButton() {
    return this.page.getByLabel('Quick export');
  }

  getDataList() {
    return this.page.getByTestId('FileExportManager');
  }

  async delete() {
    await this.page.getByRole('button', { name: 'Popover of actions' }).click();
    await this.page.getByRole('menuitem', { name: 'Delete' }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
  }

  getManageAccessRestrictionMenuItem() {
    return this.page.getByRole('menuitem', { name: 'Manage access restriction' });
  }

  /** The "Author" section shows the createdBy org's name if visible to the current user, or "Restricted" if the org itself isn't visible to them. */
  async assertAuthor(name: string) {
    await expect(this.getTextForHeading('Author', name)).toBeVisible();
  }

  async assertAuthorRestricted() {
    await expect(this.getTextForHeading('Author', 'Restricted')).toBeVisible();
  }

  /** Asserts the current user's access level to this report via visible UI affordances: the report title (canView), "Update" button (canEdit), and "Manage access restriction" menu item (canManageAuthorizedMembers). */
  async assertReportAccess({ name, canView = true, canEdit = false, canManageAuthorizedMembers = false }: {
    name: string;
    canView?: boolean;
    canEdit?: boolean;
    canManageAuthorizedMembers?: boolean;
  }) {
    if (!canView) {
      await this.getTitle(name).waitFor({ state: 'hidden' });
      return;
    }
    await this.getTitle(name).waitFor({ state: 'visible' });

    if (canEdit) {
      await this.getEditButton().waitFor({ state: 'visible' });
    } else {
      await this.getEditButton().waitFor({ state: 'hidden' });
    }

    // The popover can also be shown for reasons unrelated to this report's access rights (e.g.
    // "Enroll in playbook"), so only the access-gated "Manage access restriction" item is checked.
    const popoverButton = this.page.getByRole('button', { name: 'Popover of actions' });
    if (canManageAuthorizedMembers) {
      await popoverButton.waitFor({ state: 'visible' });
      await popoverButton.click();
      await this.getManageAccessRestrictionMenuItem().waitFor({ state: 'visible' });
      await this.page.keyboard.press('Escape');
    } else if (await popoverButton.isVisible()) {
      await popoverButton.click();
      await this.getManageAccessRestrictionMenuItem().waitFor({ state: 'hidden' });
      await this.page.keyboard.press('Escape');
    }
  }
}
