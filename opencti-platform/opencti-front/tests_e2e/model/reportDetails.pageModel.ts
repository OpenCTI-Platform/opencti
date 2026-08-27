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

  /** The "Author" section (`StixDomainObjectOverview.jsx`) shows the createdBy org's name if
   * visible to the current user, or the literal "Restricted" chip if the org itself isn't
   * visible to them (backend returns a stub entity named "Restricted", not null/empty). */
  async assertAuthor(name: string) {
    await expect(this.getTextForHeading('Author', name)).toBeVisible();
  }

  async assertAuthorRestricted() {
    await expect(this.getTextForHeading('Author', 'Restricted')).toBeVisible();
  }

  /**
   * Asserts the current (already-logged-in) user's access level to this report, based on which
   * UI affordances are visible: the report title (canView), the "Update" edit button (canEdit),
   * and the popover's "Manage access restriction" menu item (canManageAuthorizedMembers).
   */
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

    // The popover (`ContainerHeader.jsx`'s `displayPopoverMenu`) can also be shown for reasons
    // unrelated to this report's access rights - e.g. "Enroll in playbook" only depends on the
    // AUTOMATION capability, not on `currentUserAccessRight`. So its overall visibility can't be
    // asserted here; only the "Manage access restriction" item (which IS access-right-gated) is
    // checked, and only if the popover happens to be open.
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
