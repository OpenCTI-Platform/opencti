import { Page } from '@playwright/test';
import SelectFieldPageModel from './field/SelectField.pageModel';
import DateFieldPageModel from './field/DateField.pageModel';

export default class DashboardDetailsPage {
  accessSelect = new SelectFieldPageModel(this.page, 'Relative time', false);
  startDateField = new DateFieldPageModel(this.page, 'Start date');
  endDateField = new DateFieldPageModel(this.page, 'End date');
  constructor(private page: Page) {}

  getDashboardDetailsPage() {
    return this.page.getByTestId('dashboard-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getActionsPopover() {
    return this.page.getByLabel('Popover of actions');
  }

  getActionButton(name: string) {
    return this.page.getByRole('menuitem', { name });
  }

  getEditButton() {
    return this.page.getByRole('button', { name: 'Update' });
  }

  getExportButton() {
    return this.page.getByRole('button', { name: 'Export', exact: true });
  }

  async delete() {
    await this.page.getByRole('button', { name: 'Popover of actions workspace' }).click();
    await this.page.getByRole('menuitem', { name: 'Delete' }).click();
    return this.page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
  }

  getConfirmButton() {
    return this.page.getByRole('button', { name: 'Confirm' });
  }

  getDuplicateButton() {
    return this.page.getByRole('button', { name: 'Duplicate' });
  }

  getExportPDFButton() {
    return this.page.getByRole('button', { name: 'Export to PDF' });
  }

  getExportPDFButtonThemeMenu(darkOrLight: string) {
    return this.page.getByRole('menuitem', { name: darkOrLight });
  }
}
