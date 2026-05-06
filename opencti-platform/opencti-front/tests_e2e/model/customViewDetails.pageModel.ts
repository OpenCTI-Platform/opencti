import { Page } from '@playwright/test';
import DashboardWidgetsPageModel from './DashboardWidgets.pageModel';

export default class CustomViewDetailsPage {
  widgets = new DashboardWidgetsPageModel(this.page);

  constructor(private page: Page) {}

  getTitle(name: string) {
    return this.page.getByRole('heading', { name, exact: true });
  }

  getEditButton() {
    return this.page.getByRole('button', { name: 'Update' });
  }

  getActionsPopover() {
    return this.page.getByLabel('Popover of custom view actions');
  }

  getActionButton(name: string) {
    return this.page.getByRole('menuitem', { name });
  }

  getConfirmButton() {
    return this.page.getByRole('button', { name: 'Confirm' });
  }

  getDuplicateButton() {
    return this.page.getByRole('button', { name: 'Duplicate' });
  }

  getExportButton() {
    return this.page.getByRole('button', { name: 'Export' });
  }

  getEnableToggle() {
    return this.page.getByRole('button', { name: 'Enable' });
  }

  getDisableToggle() {
    return this.page.getByRole('button', { name: 'Disable' });
  }

  getDefaultToggle() {
    return this.page.getByRole('checkbox', { name: 'Set as default custom view' });
  }

  getCloseButton() {
    return this.page.getByRole('button', { name: 'Close' });
  }

  getViewIsEnabledTag() {
    return this.page.getByText('View is enabled');
  }

  getViewIsDisabledTag() {
    return this.page.getByText('View is disabled');
  }

  async delete() {
    await this.getActionsPopover().click();
    await this.getActionButton('Delete').click();
    await this.getConfirmButton().click();
  }
}
