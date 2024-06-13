import { Page } from '@playwright/test';
import SelectFieldPageModel from './field/SelectField.pageModel';
import DateFieldPageModel from './field/DateField.pageModel';

export default class DashboardDetailsPage {
  accessSelect = new SelectFieldPageModel(this.page, 'Relative time', false);
  startDateField = new DateFieldPageModel(this.page, 'Start date');

  constructor(private page: Page) {}

  getDashboardDetailsPage() {
    return this.page.getByTestId('dashboard-details-page');
  }

  getTitle(name: string) {
    return this.page.getByRole('heading', { name });
  }

  getActionsPopover() {
    return this.page.getByLabel('Workspace popover of actions');
  }

  getActionButton(name: string) {
    return this.page.getByRole('menuitem', { name });
  }

  getDeleteButton() {
    return this.page.getByRole('button', { name: 'Delete' });
  }

  getDuplicateButton() {
    return this.page.getByRole('button', { name: 'Duplicate' });
  }
}
