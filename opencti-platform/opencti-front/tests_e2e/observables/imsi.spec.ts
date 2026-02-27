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
  await observableForm.validateBulk();
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
