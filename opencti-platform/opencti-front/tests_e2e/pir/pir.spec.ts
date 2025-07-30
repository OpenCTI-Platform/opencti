import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import PirPage from '../model/pir.pageModel';
import PirFormPageModel from '../model/form/pirForm.pageModel';
import PirDetailsPageModel from '../model/pirDetails.pageModel';

test('Pir CRUD', { tag: ['@pir', '@mutation'] }, async ({ page }) => {
  const leftNavigation = new LeftBarPage(page);
  const pirPage = new PirPage(page);
  const pirForm = new PirFormPageModel(page);
  const pirDetails = new PirDetailsPageModel(page);

  await pirPage.goto();
  await pirPage.navigateFromMenu();
  // open nav bar once and for all
  await leftNavigation.open();

  // region Create PIR
  // -----------------

  await pirPage.openCreateForm();
  await expect(pirForm.getCreateTitle()).toBeVisible();

  const pirName = `PIR - ${uuid()}`;
  await pirForm.selectType('threat landscape');
  await pirForm.getNextButton().click();
  await pirForm.nameField.fill(pirName);
  await pirForm.getNextButton().click();
  await pirForm.locationsField.selectOption('France');
  await pirForm.industriesField.selectOption('Agriculture');
  await pirForm.getCreateButton().click();

  await pirPage.getItemFromList(pirName).click();
  await expect(pirDetails.getTitle(pirName)).toBeVisible();

  // ---------
  // endregion

  // region Navigate through tabs
  // ----------------------------

  await pirDetails.tabs.goToThreatsTab();
  await pirDetails.tabs.goToAnalysesTab();
  await pirDetails.tabs.goToHistoryTab();
  await pirDetails.tabs.goToOverviewTab();

  // ---------
  // endregion
});
