import { Page } from '@playwright/test';
import FiltersPageModel from './filters.pageModel';
import TextFieldPageModel from './field/TextField.pageModel';
import SelectFieldPageModel from './field/SelectField.pageModel';

type WidgetPerspective = 'Entities' | 'Knowledge graph' | 'Activity & history';

export default class DashboardWidgetsPageModel {
  private labelPerspective?: 'entities' | 'relationships' | 'audits';

  filters = new FiltersPageModel(this.page);
  titleField = new TextFieldPageModel(this.page, 'Title', 'text');
  dateAttribute = new SelectFieldPageModel(this.page, 'Relative time', false);

  constructor(private page: Page) {}

  getCreateWidgetButton() {
    return this.page.getByLabel('Create', { exact: true });
  }

  async openWidgetModal() {
    await this.page.getByLabel('Create', { exact: true }).hover();
    return this.page.getByLabel('Create a widget', { exact: true }).click();
  }

  selectWidget(widgetName: string) {
    return this.page.getByLabel(widgetName, { exact: true }).click();
  }

  selectPerspective(perspective: WidgetPerspective) {
    if (perspective === 'Entities') this.labelPerspective = 'entities';
    if (perspective === 'Knowledge graph') this.labelPerspective = 'relationships';
    if (perspective === 'Activity & history') this.labelPerspective = 'audits';
    return this.page.getByLabel(perspective, { exact: true }).click();
  }

  fillLabel(label: string) {
    const filtersLabelField = new TextFieldPageModel(this.page, `label (${this.labelPerspective})`, 'text');
    return filtersLabelField.fill(label);
  }

  validateFilters() {
    return this.page.getByRole('button', { name: 'validate' }).click();
  }

  createWidget() {
    return this.page.getByRole('button', { name: 'create' }).click();
  }

  getItemFromWidgetList(name: string) {
    return this.page.getByTestId(name);
  }

  getItemFromWidgetTimeline(name: string) {
    return this.page.getByText(name);
  }

  getActionsWidgetsPopover() {
    return this.page.getByLabel('Widget popover of actions');
  }

  getActionButton(name: string) {
    return this.page.getByRole('menuitem', { name });
  }

  getDeleteButton() {
    return this.page.getByRole('button', { name: 'Delete' });
  }

  getIconFromWidgetTimeline() {
    return this.page.getByTestId('BiohazardIcon').first();
  }

  getWidgetNumberValue(name: string, value: string) {
    return this.page.getByRole('heading', { name }).locator('..').getByText(value);
  }

  // region Premade widgets

  async createListOfMalwaresWidget() {
    await this.openWidgetModal();
    await this.selectWidget('List');
    await this.selectPerspective('Entities');
    await this.fillLabel('Malwares');
    await this.filters.addFilter('Entity type', 'Malware', false);
    await this.filters.addFilter('Label', 'e2e');
    await this.validateFilters();
    await this.titleField.fill('List of malwares');
    await this.createWidget();
  }

  async createTimelineOfMalwaresWidget() {
    await this.openWidgetModal();
    await this.selectWidget('Timeline');
    await this.selectPerspective('Entities');
    await this.fillLabel('Malware');
    await this.filters.addFilter('Entity type', 'Malware', false);
    await this.filters.addFilter('Label', 'e2e');
    await this.validateFilters();
    await this.titleField.fill('Timeline of malwares');
    await this.createWidget();
  }

  async createNumberOfEntities() {
    await this.openWidgetModal();
    await this.selectWidget('Number');
    await this.selectPerspective('Entities');
    await this.filters.addFilter('Entity type', 'Entity', false);
    await this.filters.addFilter('Label', 'e2e');
    await this.validateFilters();
    await this.titleField.fill('Number of entities');
    await this.dateAttribute.selectOption('created (Functional date)');
    await this.createWidget();
  }

  // endregion
}
