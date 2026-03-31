import { Page } from '@playwright/test';
import FiltersPageModel from './filters.pageModel';
import TextFieldPageModel from './field/TextField.pageModel';
import SelectFieldPageModel from './field/SelectField.pageModel';

type WidgetPerspective = 'Entities' | 'Knowledge graph' | 'Activity & history';

export default class DashboardWidgetsPageModel {
  private labelPerspective?: 'entities' | 'relationships' | 'audits';

  filters = new FiltersPageModel(this.page, this.page.getByTestId('widget-selection-0'));
  subFilters = new FiltersPageModel(this.page, this.page.getByTestId('widget-selection-1'));
  titleField = new TextFieldPageModel(this.page, 'Title', 'text');
  dateAttributeMain = new SelectFieldPageModel(this.page, 'Relative time', false, this.page.getByTestId('widget-params-selection-0'));
  dateAttributeSub = new SelectFieldPageModel(this.page, 'Relative time', false, this.page.getByTestId('widget-params-selection-1'));
  attributeFieldMain = new SelectFieldPageModel(this.page, 'Attribute', false, this.page.getByTestId('widget-params-selection-0'));
  attributeFieldSub = new SelectFieldPageModel(this.page, 'Attribute', false, this.page.getByTestId('widget-params-selection-1'));

  constructor(private page: Page) {}

  getCreateWidgetButton() {
    return this.page.getByRole('button', { name: 'Create Widget' });
  }

  async openWidgetModal() {
    return this.page.getByRole('button', { name: 'Create Widget' }).click();
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

  getConfirmButton() {
    return this.page.getByRole('button', { name: 'Confirm' });
  }

  getIconFromWidgetTimeline() {
    return this.page.getByTestId('BiohazardIcon').first();
  }

  getWidgetNumberValue(name: string, value: string) {
    return this.page.getByText(name).locator('../../..').getByText(value);
  }

  addEntitiesSelection() {
    return this.page.getByRole('button', { name: 'entities' }).click();
  }

  // region Premade widgets

  async createListOfMalwaresWidget() {
    await this.openWidgetModal();
    await this.selectWidget('List');
    await this.selectPerspective('Entities');
    await this.fillLabel('Malwares');
    await this.filters.addFilter('Entity type', 'Malware');
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
    await this.filters.addFilter('Entity type', 'Malware');
    await this.filters.addFilter('Label', 'e2e');
    await this.validateFilters();
    await this.titleField.fill('Timeline of malwares');
    await this.createWidget();
  }

  async createNumberOfEntities() {
    await this.openWidgetModal();
    await this.selectWidget('Number');
    await this.selectPerspective('Entities');
    await this.filters.addFilter('Entity type', 'Entity');
    await this.filters.addFilter('Label', 'e2e');
    await this.validateFilters();
    await this.titleField.fill('Number of entities');
    await this.dateAttributeMain.selectOption('created (Functional date)');
    await this.createWidget();
  }

  async createHorizontalBreakdownOfMalwares() {
    await this.openWidgetModal();
    await this.selectWidget('Horizontal Bar');
    await this.selectPerspective('Knowledge graph');
    await this.filters.addFilter('Source type', 'Malware');
    await this.filters.addFilter('Relationship type', 'targets');
    await this.addEntitiesSelection();
    await this.subFilters.addFilter('Entity type', 'Malware');
    await this.validateFilters();
    await this.attributeFieldMain.selectOption('Entity');
    await this.attributeFieldSub.selectOption('Malware_types');
    await this.createWidget();
  }

  // endregion
}
