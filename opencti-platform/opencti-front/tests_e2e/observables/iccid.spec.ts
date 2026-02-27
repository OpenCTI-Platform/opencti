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
  await observableForm.validateBulk();
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
