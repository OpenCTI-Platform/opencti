import { expect, test } from '../fixtures/baseFixtures';
import SSOPage from '../model/sso.pageModel';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import SSOFormPageModel from '../model/form/ssoForm.pageModel';

/**
 * Content of the test
 * -------------------
 * Create a SSO
 * Navigate through SSO tabs
 * Delete SSO
 */
test('SSO definition CRUD', { tag: ['@sso', '@mutation', '@ee'] }, async ({ page, request }) => {
  const leftNavigation = new LeftBarPage(page);
  const ssoPage = new SSOPage(page);
  const ssoForm = new SSOFormPageModel(page);

  await ssoPage.goto();
  await ssoPage.navigateFromMenu();
  // open nav bar once and for all
  await leftNavigation.open();

  // region Create SSO
  // -----------------

  await ssoPage.getCreateButton().click();
  await ssoPage.getCreateSAML().click();
  await expect(ssoForm.getCreateTitle()).toBeVisible();
  //   // Step 1
  const ssoName = 'e2e SSO Authentication';
  await ssoForm.nameField.fill('');
  await expect(ssoForm.getCreateButton()).toBeDisabled();
  await ssoForm.nameField.fill(ssoName);
  await expect(ssoForm.getCreateButton()).toBeEnabled();
  await ssoForm.descriptionField.fill('DESCRIPTION test');
  await ssoForm.issuerField.fill('issuer test');
  await ssoForm.samlURLField.fill('issuer test');
  await ssoForm.idpCertField.fill('issuer test');
  await ssoForm.privateKeyField.selectOption('Set a new secret');
  await ssoForm.valuePKField.fill('MIIEpAIBAAKCAQEAoHLhB8sf4e3NbRayxNAQ1fhJIS4XqSsh20opCQIWyykBTPUedGHOB89JwTTw0KzX/uWr9nBWv+Hl9QtIZ9UgVlF4rlD0Au7/RqSTLPsiwidwMevJ7o1CteQu9mJpbbE2TXKSrT4kOr3Jthis89q3Ur11gdh6StMGlyL581C6aPIl8H0l5skKrrw0or02nphJDo68PjXRfOATrUHjlW28Auc9BEC1d8kk8p78s980DZMMNLZr1XrwLhu9LkkcOw2c5PHo16IisYAVzbupQJkQgUTshu8ivZ4vZ4ERDHpaL4ckpQFsJfK0QaEXIvaMH/POt6/M6StD8/4bHv4hfEm9QIDAQABAoIBAD5I+kRNPP42k1Vy');
//   // Step 2
//   await expect(ssoForm.getCreateButton()).toBeDisabled();
//   await ssoForm.locationsField.selectOption('France');
//   await expect(ssoForm.getCreateButton()).toBeEnabled();
//   await ssoForm.industriesField.selectOption('Agriculture');
//   await ssoForm.getCreateButton().click();
//
//   await ssoPage.getItemFromList(ssoName).click();
//   await pirDetails.toggleDetails();
//   await expect(pirDetails.getTitle(pirName)).toBeVisible();
//   await expect(pirDetails.getDescription('e2e PIR description')).toBeVisible();
//
//   // ---------
//   // endregion
//
//   // region Navigate through tabs
//   // ----------------------------
//
//   await pirDetails.tabs.goToThreatsTab();
//   await pirDetails.tabs.goToAnalysesTab();
//   await pirDetails.tabs.goToActivitiesTab();
//   await pirDetails.tabs.goToOverviewTab();
//
//   // ---------
//   // endregion
//
//   // region Create a relation that flags entity
//   // ------------------------------------------
//
//   await expect(pirDetails.getEntityTypeCount('Malware')).toContainText('0');
//   await addRelationship(request, {
//     relationship_type: 'targets',
//     toId: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971',
//     fromId: 'malware--48534a79-a9d7-4c34-a292-f5f102d26dea',
//     createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
//   });
//
//   // ---------
//   // endregion
//
//   // region Control tab Overview after flagging
//   // ------------------------------------------
//
//   const waitForFlagging = async () => {
//     await pirPage.navigateFromMenu();
//     await pirPage.getItemFromList(pirName).click();
//     const text = await pirDetails.getEntityTypeCount('Malware').innerText();
//     return text === '1';
//   };
//   await awaitUntilCondition(waitForFlagging, 5000, 20);
//   await expect(pirDetails.getEntityTypeCount('Malware')).toContainText('1');
//   await expect(pirDetails.getTopAuthorEntities('John Doe')).toBeVisible();
//   await expect(pirDetails.getTopAuthorRelationships('ANSSI')).toBeVisible();
//
//   const historyItemName = 'Malware E2E dashboard - Malware - month ago added to PIR';
//   const waitForHistory = async () => {
//     await pirPage.navigateFromMenu();
//     await pirPage.getItemFromList(pirName).click();
//     return pirDetails.getNewsFeedItem(historyItemName).isVisible();
//   };
//   await awaitUntilCondition(waitForHistory, 5000, 20);
//   await expect(pirDetails.getNewsFeedItem(historyItemName)).toBeVisible();
//
//   // ---------
//   // endregion
//
//   // region Control tab Threats after flagging
//   // -----------------------------------------
//
//   await pirDetails.tabs.goToThreatsTab();
//   await expect(pirDetails.dataTable.container.getByText('E2E dashboard - Malware - month ago')).toBeVisible();
//   await expect(pirDetails.dataTable.container.getByText('50')).toBeVisible();
//
//   // ---------
//   // endregion
//
//   // region Control tab History after flagging
//   // -----------------------------------------
//
//   await pirDetails.tabs.goToActivitiesTab();
//   await expect(pirDetails.dataTable.container.getByText(historyItemName)).toBeVisible();
//
//   // ---------
//   // endregion
//
//   // region Delete relation that flags entity
//   // ----------------------------------------
//
//   await pirDetails.tabs.goToOverviewTab();
//   await expect(pirDetails.getEntityTypeCount('Malware')).toContainText('1');
//   await deleteRelationship(request, {
//     relationship_type: 'targets',
//     toId: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971',
//     fromId: 'malware--48534a79-a9d7-4c34-a292-f5f102d26dea',
//   });
//
//   // ---------
//   // endregion
//
//   // region Control tab Overview after unflagging
//   // --------------------------------------------
//
//   const waitForUnflagging = async () => {
//     await pirPage.navigateFromMenu();
//     await pirPage.getItemFromList(pirName).click();
//     const text = await pirDetails.getEntityTypeCount('Malware').innerText();
//     return text === '0';
//   };
//   await awaitUntilCondition(waitForUnflagging, 5000, 20);
//   await expect(pirDetails.getEntityTypeCount('Malware')).toContainText('0');
//
//   // ---------
//   // endregion
//
//   // region Delete the report
//   // ------------------------
//
//   await pirDetails.delete();
//   await pirPage.navigateFromMenu();
//   await expect(pirPage.getItemFromList(pirName)).toBeHidden();
//
//   // ---------
//   // endregion
});
