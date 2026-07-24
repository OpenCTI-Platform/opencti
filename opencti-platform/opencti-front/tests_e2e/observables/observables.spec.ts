import { faker } from '@faker-js/faker';
import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import ObservableFormPage from '../model/form/observableForm.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import ObservablesPage from '../model/observable.pageModel';
import ObservableDetailsPage from '../model/observableDetails.pageModel';

// Each test uses unique generated data — safe to run in parallel
test.describe.configure({ mode: 'parallel' });

test.describe('Observables CRUD', () => {
  /**
   * Verify value validation.
   * Create an IMEI.
   * Delete IMEI.
   * Bulk creation IMEI.
   * Bulk deletion.
   */
  test('IMEI CRUD', { tag: ['@ce'] }, async ({ page }) => {
    const leftBarPage = new LeftBarPage(page);
    const observablePage = new ObservablesPage(page);
    const observableForm = new ObservableFormPage(page);
    const observableDetailsPage = new ObservableDetailsPage(page);

    await observablePage.goto();
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Observations', 'Observables');

    const imeiValid = faker.string.numeric(15);
    const imeiTooLong = faker.string.numeric(25);
    const imeiAlphanumeric = '123456789poiuyt';

    const bulkImei1 = faker.string.numeric(15);
    const bulkImei2 = faker.string.numeric(15);

    // Check validation.

    await observablePage.addNew();
    await observableForm.chooseType('IMEI');
    await observableForm.valueField.fill(imeiTooLong);
    await observableForm.submit();
    await expect(page.getByText('IMEI values can only include digits, must be 15 to 16 characters')).toBeVisible();
    await observableForm.cancel();

    await observablePage.addNew();
    await observableForm.chooseType('IMEI');
    await observableForm.valueField.fill(imeiAlphanumeric);
    await observableForm.submit();
    await expect(page.getByText('IMEI values can only include digits, must be 15 to 16 characters')).toBeVisible();
    await observableForm.cancel();

    // Create an IMEI.

    await observablePage.addNew();
    await observableForm.chooseType('IMEI');
    await observableForm.valueField.fill(imeiValid);
    await observableForm.submit();
    await observablePage.getItemFromList(imeiValid).click();
    await expect(observableDetailsPage.getPage()).toBeVisible();

    // Delete IMEI.

    await observableDetailsPage.delete();
    await observablePage.navigateFromMenu();
    await expect(observablePage.getItemFromList(imeiValid)).toBeHidden();

    // Bulk creation IMEI.

    await observablePage.addNew();
    await observableForm.chooseType('IMEI');
    await observableForm.openBulk();
    await observableForm.bulkValuesField.fill(`${bulkImei1}\n${bulkImei2}`);
    await observableForm.validateBulk(2);
    await observableForm.submit();
    await observableForm.closeBulk();

    // Bulk deletion.

    await observablePage.getItemFromList(bulkImei1).click();
    await observableDetailsPage.delete();
    await observablePage.navigateFromMenu();
    await expect(observablePage.getItemFromList(bulkImei1)).toBeHidden();
    await observablePage.getItemFromList(bulkImei2).click();
    await observableDetailsPage.delete();
    await observablePage.navigateFromMenu();
    await expect(observablePage.getItemFromList(bulkImei2)).toBeHidden();
  });

  /**
   * Verify value validation.
   * Create an ICCID.
   * Delete ICCID.
   * Bulk creation ICCID.
   * Bulk deletion.
   */
  test('ICCID CRUD', { tag: ['@ce'] }, async ({ page }) => {
    const leftBarPage = new LeftBarPage(page);
    const observablePage = new ObservablesPage(page);
    const observableForm = new ObservableFormPage(page);
    const observableDetailsPage = new ObservableDetailsPage(page);

    await observablePage.goto();
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Observations', 'Observables');

    const iccidValid = faker.string.numeric(19);
    const iccidTooLong = faker.string.numeric(25);
    const iccidAlphanumeric = '123456789poiuyt';

    const bulkIccid1 = faker.string.numeric(19);
    const bulkIccid2 = faker.string.numeric(19);

    // Check validation.

    await observablePage.addNew();
    await observableForm.chooseType('ICCID');
    await observableForm.valueField.fill(iccidTooLong);
    await observableForm.submit();
    await expect(page.getByText('ICCID values can only include digits, must be 18 to 22 characters')).toBeVisible();
    await observableForm.cancel();

    await observablePage.addNew();
    await observableForm.chooseType('ICCID');
    await observableForm.valueField.fill(iccidAlphanumeric);
    await observableForm.submit();
    await expect(page.getByText('ICCID values can only include digits, must be 18 to 22 characters')).toBeVisible();
    await observableForm.cancel();

    // Create an ICCID.

    await observablePage.addNew();
    await observableForm.chooseType('ICCID');
    await observableForm.valueField.fill(iccidValid);
    await observableForm.submit();
    await observablePage.getItemFromList(iccidValid).click();
    await expect(observableDetailsPage.getPage()).toBeVisible();

    // Delete ICCID.

    await observableDetailsPage.delete();
    await observablePage.navigateFromMenu();
    await expect(observablePage.getItemFromList(iccidValid)).toBeHidden();

    // Bulk creation ICCID.

    await observablePage.addNew();
    await observableForm.chooseType('ICCID');
    await observableForm.openBulk();
    await observableForm.bulkValuesField.fill(`${bulkIccid1}\n${bulkIccid2}`);
    await observableForm.validateBulk(2);
    await observableForm.submit();
    await observableForm.closeBulk();

    // Bulk deletion.

    await observablePage.getItemFromList(bulkIccid1).click();
    await observableDetailsPage.delete();
    await observablePage.navigateFromMenu();
    await expect(observablePage.getItemFromList(bulkIccid1)).toBeHidden();
    await observablePage.getItemFromList(bulkIccid2).click();
    await observableDetailsPage.delete();
    await observablePage.navigateFromMenu();
    await expect(observablePage.getItemFromList(bulkIccid2)).toBeHidden();
  });

  /**
   * Verify value validation.
   * Create an IMSI.
   * Delete IMSI.
   * Bulk creation IMSI.
   * Bulk deletion.
   */
  test('IMSI CRUD', { tag: ['@ce'] }, async ({ page }) => {
    const leftBarPage = new LeftBarPage(page);
    const observablePage = new ObservablesPage(page);
    const observableForm = new ObservableFormPage(page);
    const observableDetailsPage = new ObservableDetailsPage(page);

    await observablePage.goto();
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Observations', 'Observables');

    const imsiValid = faker.string.numeric(15);
    const imsiTooLong = faker.string.numeric(25);
    const imsiAlphanumeric = '123456789poiuyt';

    const bulkImsi1 = faker.string.numeric(15);
    const bulkImsi2 = faker.string.numeric(15);

    // Check validation.

    await observablePage.addNew();
    await observableForm.chooseType('IMSI');
    await observableForm.valueField.fill(imsiTooLong);
    await observableForm.submit();
    await expect(page.getByText('IMSI values can only include digits, must be 14 to 15 characters')).toBeVisible();
    await observableForm.cancel();

    await observablePage.addNew();
    await observableForm.chooseType('IMSI');
    await observableForm.valueField.fill(imsiAlphanumeric);
    await observableForm.submit();
    await expect(page.getByText('IMSI values can only include digits, must be 14 to 15 characters')).toBeVisible();
    await observableForm.cancel();

    // Create an IMSI.

    await observablePage.addNew();
    await observableForm.chooseType('IMSI');
    await observableForm.valueField.fill(imsiValid);
    await observableForm.submit();
    await observablePage.getItemFromList(imsiValid).click();
    await expect(observableDetailsPage.getPage()).toBeVisible();

    // Delete IMSI.

    await observableDetailsPage.delete();
    await observablePage.navigateFromMenu();
    await expect(observablePage.getItemFromList(imsiValid)).toBeHidden();

    // Bulk creation IMSI.

    await observablePage.addNew();
    await observableForm.chooseType('IMSI');
    await observableForm.openBulk();
    await observableForm.bulkValuesField.fill(`${bulkImsi1}\n${bulkImsi2}`);
    await observableForm.validateBulk(2);
    await observableForm.submit();
    await observableForm.closeBulk();

    // Bulk deletion.

    await observablePage.getItemFromList(bulkImsi1).click();
    await observableDetailsPage.delete();
    await observablePage.navigateFromMenu();
    await expect(observablePage.getItemFromList(bulkImsi1)).toBeHidden();
    await observablePage.getItemFromList(bulkImsi2).click();
    await observableDetailsPage.delete();
    await observablePage.navigateFromMenu();
    await expect(observablePage.getItemFromList(bulkImsi2)).toBeHidden();
  });

  /**
   * Create an email message.
   */
  test('Email message CRUD', { tag: ['@ce'] }, async ({ page }) => {
    const leftBarPage = new LeftBarPage(page);
    const observablePage = new ObservablesPage(page);
    const observableForm = new ObservableFormPage(page);
    const observableDetailsPage = new ObservableDetailsPage(page);

    await observablePage.goto();
    await leftBarPage.open();
    await leftBarPage.clickOnMenu('Observations', 'Observables');

    const emailMessage = {
      subject: `My super email - ${uuid()}`,
      body: `This is a super email you must read - ${uuid()}`,
    };

    await observablePage.addNew();
    await observableForm.chooseType('Email message');
    await observableForm.emailMessageBodyField.fill(emailMessage.body);
    await observableForm.emailMessageSubjectField.fill(emailMessage.subject);
    await observableForm.submit();
    await observablePage.getItemFromList(emailMessage.body).click();
    await expect(observableDetailsPage.getPage()).toBeVisible();
  });
});
