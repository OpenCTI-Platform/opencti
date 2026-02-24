import { faker } from '@faker-js/faker';
import { expect, test } from '../fixtures/baseFixtures';
import ObservableFormPage from '../model/form/observableForm.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import ObservablesPage from '../model/observable.pageModel';
import ObservableDetailsPage from '../model/observableDetails.pageModel';

/**
 * Content of the test
 * -------------------
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
  await observableForm.validateBulk();
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
