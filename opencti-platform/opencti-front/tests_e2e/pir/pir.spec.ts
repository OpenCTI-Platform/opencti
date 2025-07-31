import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import PirPage from '../model/pir.pageModel';
import PirFormPageModel from '../model/form/pirForm.pageModel';
import PirDetailsPageModel from '../model/pirDetails.pageModel';
import { addRelationship } from '../dataForTesting/relationship.data';
import { awaitUntilCondition } from '../utils';

/**
 * Content of the test
 * -------------------
 * Create a PIR
 * Navigate through PIR tabs
 * Test flag entities
 * Delete PIR
 */
test('Pir CRUD', { tag: ['@pir', '@mutation'] }, async ({ page, request }) => {
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
  // Step 1
  const pirName = `PIR - ${uuid()}`;
  await pirForm.selectType('threat landscape');
  await pirForm.getNextButton().click();
  // Step 2
  await pirForm.nameField.fill('');
  await expect(pirForm.getNextButton()).toBeDisabled();
  await pirForm.nameField.fill(pirName);
  await expect(pirForm.getNextButton()).toBeEnabled();
  await pirForm.descriptionField.fill('e2e PIR description');
  await pirForm.rescanPeriodField.selectOption('No rescan');
  await pirForm.getNextButton().click();
  // Step 3
  await expect(pirForm.getCreateButton()).toBeDisabled();
  await pirForm.locationsField.selectOption('France');
  await expect(pirForm.getCreateButton()).toBeEnabled();
  await pirForm.industriesField.selectOption('Agriculture');
  await pirForm.getCreateButton().click();

  await pirPage.getItemFromList(pirName).click();
  await expect(pirDetails.getTitle(pirName)).toBeVisible();
  await expect(pirDetails.getDescription('e2e PIR description')).toBeVisible();

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

  // region Create a relation that flags entity
  // ------------------------------------------

  await expect(pirDetails.getEntityTypeCount('Malware')).toContainText('0');
  await addRelationship(request, {
    relationship_type: 'targets',
    toId: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971',
    fromId: 'malware--48534a79-a9d7-4c34-a292-f5f102d26dea',
    createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
  });

  const waitForManager = async () => {
    await pirDetails.tabs.goToHistoryTab();
    await pirDetails.tabs.goToOverviewTab();
    const text = await pirDetails.getEntityTypeCount('Malware').innerText();
    return text === '1';
  };
  await awaitUntilCondition(waitForManager, 5000);
  await expect(pirDetails.getEntityTypeCount('Malware')).toContainText('1');

  // ---------
  // endregion

  // region Delete the report
  // ------------------------

  await pirDetails.delete();
  await pirPage.navigateFromMenu();
  await expect(pirPage.getItemFromList(pirName)).toBeHidden();

  // ---------
  // endregion
});
