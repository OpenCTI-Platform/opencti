import { Page } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import ReportPage from '../model/report.pageModel';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import ReportFormPage from '../model/form/reportForm.pageModel';
import ContainerObservablesPage from '../model/containerObservables.pageModel';
import ContainerAddObservablesPage from '../model/containerAddObservables.pageModel';
import ObservableFormPage from '../model/form/observableForm.pageModel';
import ObservablesPage from '../model/observable.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import { patchEntitySetting } from '../dataForTesting/entitySetting.data';

/**
 * An observable created from a report's "Add observables" panel is added to the report,
 * with a message offering Undo.
 */
test.describe('Objects created from a container panel are added to the container', { tag: ['@ce'] }, () => {
  const nowTime = `${new Date().getTime()}`;
  // Values unique to the run: an observable that already exists would be upserted
  const suffix = Number(nowTime.slice(-4)) % 250;

  const openNewReportObservablesPanel = async (page: Page, reportName: string) => {
    const reportPage = new ReportPage(page);
    const reportForm = new ReportFormPage(page);
    const reportDetailsPage = new ReportDetailsPage(page);
    const containerObservablesPage = new ContainerObservablesPage(page);
    await reportPage.goto();
    await new LeftBarPage(page).open();
    await reportPage.openNewReportForm();
    await reportForm.nameField.fill(reportName);
    await reportPage.getCreateReportButton().click();
    await reportPage.getItemFromList(reportName).click();
    await expect(reportDetailsPage.getPage()).toBeVisible();
    await reportDetailsPage.tabs.goToObservablesTab();
    await expect(containerObservablesPage.getPage()).toBeVisible();
    await containerObservablesPage.getAddObservableListButton().click();
  };

  test.beforeEach(async ({ request }) => {
    await patchEntitySetting(request, 'Report', 'enforce_reference', false);
  });

  test('created observable is added to the report', async ({ page }) => {
    const containerObservablesPage = new ContainerObservablesPage(page);
    const addObservablesPage = new ContainerAddObservablesPage(page);
    const ip = `10.21.1.${suffix}`;

    await openNewReportObservablesPanel(page, `Auto add observable ${nowTime}`);
    await addObservablesPage.createNewIPV4Observable(ip);

    await expect(addObservablesPage.getAddedMessage()).toContainText('created and added to the');
    await addObservablesPage.getCloseObservablesListButton().click();
    await expect(containerObservablesPage.getObservableInContainer(`IPv4 address ${ip}`)).toBeVisible();
  });

  test('untick after auto-add removes it', async ({ page }) => {
    const containerObservablesPage = new ContainerObservablesPage(page);
    const addObservablesPage = new ContainerAddObservablesPage(page);
    const ip = `10.21.2.${suffix}`;

    await openNewReportObservablesPanel(page, `Auto add untick ${nowTime}`);
    await addObservablesPage.createNewIPV4Observable(ip);
    await expect(addObservablesPage.getAddedMessage()).toBeVisible();
    await addObservablesPage.getObservable(`IPv4 address ${ip}`).click();
    await addObservablesPage.getCloseObservablesListButton().click();

    await expect(containerObservablesPage.getObservableInContainer(`IPv4 address ${ip}`)).toBeHidden();
  });

  test('bulk created observables are all added', async ({ page }) => {
    const containerObservablesPage = new ContainerObservablesPage(page);
    const addObservablesPage = new ContainerAddObservablesPage(page);
    const observableForm = new ObservableFormPage(page);
    const ips = [`10.21.3.${suffix}`, `10.21.4.${suffix}`];

    await openNewReportObservablesPanel(page, `Auto add bulk ${nowTime}`);
    await addObservablesPage.getAddNewObservableButton().click();
    await addObservablesPage.getIPV4ButtonInNewObservable().click();
    await observableForm.openBulk();
    await observableForm.bulkValuesField.fill(`${ips[0]}\n${ips[1]}\nnot-an-ip`);
    await observableForm.validateBulk(3);
    await observableForm.submit();

    await expect(addObservablesPage.getAddedMessage()).toContainText('2 observables added to the');
    await observableForm.closeBulk();
    await addObservablesPage.getCloseObservablesListButton().click();
    await expect(containerObservablesPage.getObservableInContainer(`IPv4 address ${ips[0]}`)).toBeVisible();
    await expect(containerObservablesPage.getObservableInContainer(`IPv4 address ${ips[1]}`)).toBeVisible();
  });

  test('undo removes the created observable from the report', async ({ page }) => {
    const containerObservablesPage = new ContainerObservablesPage(page);
    const addObservablesPage = new ContainerAddObservablesPage(page);
    const observablesPage = new ObservablesPage(page);
    const ip = `10.21.5.${suffix}`;

    await openNewReportObservablesPanel(page, `Auto add undo ${nowTime}`);
    await addObservablesPage.createNewIPV4Observable(ip);
    await addObservablesPage.getUndoButton().click();
    await expect(page.getByRole('alert')).toContainText('Removed from the');
    await addObservablesPage.getCloseObservablesListButton().click();
    await expect(containerObservablesPage.getObservableInContainer(`IPv4 address ${ip}`)).toBeHidden();

    // Removed from the report, not deleted
    await observablesPage.goto();
    await expect(observablesPage.getItemFromList(ip)).toBeVisible();
  });

  test('undo after closing the panel', async ({ page }) => {
    const containerObservablesPage = new ContainerObservablesPage(page);
    const addObservablesPage = new ContainerAddObservablesPage(page);
    const ip = `10.21.6.${suffix}`;

    await openNewReportObservablesPanel(page, `Auto add undo closed ${nowTime}`);
    await addObservablesPage.createNewIPV4Observable(ip);
    await expect(addObservablesPage.getAddedMessage()).toBeVisible();
    await addObservablesPage.getCloseObservablesListButton().click();
    await expect(containerObservablesPage.getObservableInContainer(`IPv4 address ${ip}`)).toBeVisible();
    await addObservablesPage.getUndoButton().click();

    await expect(containerObservablesPage.getObservableInContainer(`IPv4 address ${ip}`)).toBeHidden();
  });

  test('close hides the message and keeps the object', async ({ page }) => {
    const containerObservablesPage = new ContainerObservablesPage(page);
    const addObservablesPage = new ContainerAddObservablesPage(page);
    const ip = `10.21.7.${suffix}`;

    await openNewReportObservablesPanel(page, `Auto add close ${nowTime}`);
    await addObservablesPage.createNewIPV4Observable(ip);
    await expect(addObservablesPage.getAddedMessage()).toBeVisible();
    await addObservablesPage.getCloseMessageButton().click();
    await expect(addObservablesPage.getAddedMessage()).toBeHidden();
    await addObservablesPage.getCloseObservablesListButton().click();

    await expect(containerObservablesPage.getObservableInContainer(`IPv4 address ${ip}`)).toBeVisible();
  });
});
