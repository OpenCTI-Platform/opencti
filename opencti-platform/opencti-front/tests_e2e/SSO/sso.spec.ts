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

  await ssoPage.getCreateButton();

  await ssoPage.getCreateSAML();
  await expect(ssoForm.getCreateTitle()).toBeVisible();
  // Step 1
  const ssoName = 'e2e SSO Authentication';
  await ssoForm.nameField.fill('');
  await expect(ssoForm.getCreateButton()).toBeDisabled();
  await ssoForm.nameField.fill(ssoName);
  await expect(ssoForm.getCreateButton()).toBeEnabled();
  await ssoForm.descriptionField.fill('DESCRIPTION test');
  await ssoForm.issuerField.fill('openctisaml test');
  await ssoForm.samlURLField.fill('http://localhost:9999/realms/master/protocol/saml test');
  await ssoForm.idpCertField.fill('issuer test');
  await ssoForm.privateKeyField.selectOption('Set a new secret');
  await ssoForm.valuePKField.fill('MIIEpAIBAAKCAQEAoHLhB8sf4e3NbRayxNAQ1fhJIS4XqSsh20opCQIWyykBTPUedGHOB89JwTTw0KzX/uWr9nBWv+Hl9QtIZ9UgVlF4rlD0Au7/RqSTLPsiwidwMevJ7o1CteQu9mJpbbE2TXKSrT4kOr3Jthis89q3Ur11gdh6StMGlyL581C6aPIl8H0l5skKrrw0or02nphJDo68PjXRfOATrUHjlW28Auc9BEC1d8kk8p78s980DZMMNLZr1XrwLhu9LkkcOw2c5PHo16IisYAVzbupQJkQgUTshu8ivZ4vZ4ERDHpaL4ckpQFsJfK0QaEXIvaMH/POt6/M6StD8/4bHv4hfEm9QIDAQABAoIBAD5I+kRNPP42k1Vy');
  //   // Step 2
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
  await ssoForm.getCreateButton().click();
  await expect(ssoPage.getSAMLConfig());
  // endregion

  // region Delete the report
  // ------------------------

  await ssoPage.delete();

  await expect(ssoPage.getItemFromList(ssoName)).toBeHidden();

  // ---------
  // endregion
});
