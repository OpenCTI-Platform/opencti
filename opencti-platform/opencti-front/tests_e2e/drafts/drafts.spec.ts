import DraftsPage from 'tests_e2e/model/drafts.pageModel';
import RestrictionsPage from 'tests_e2e/model/restrictions.pageModel';
import { expect, test } from '../fixtures/baseFixtures';
import LoginFormPageModel from 'tests_e2e/model/form/loginForm.pageModel';
import TopMenuProfilePage from 'tests_e2e/model/menu/topMenuProfile.pageModel';

test.describe('Drafts', () => {
  const draftName = `Draft E2E - ${Date.now()}`;
  

  test('should create and delete a draft without restrictions', async ({ page }) => {

    // create a draft
    const Drafts = new DraftsPage(page);

    await Drafts.navigate();
    await Drafts.createDraft({
      name: draftName,
    });
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    // clean up by deleting the created draft
    await Drafts.deleteDraft(draftName);
    await page.reload();
    await expect(Drafts.getDraft(draftName)).not.toBeVisible();
  });

  test('should restrict a draft to specific members', async ({ page }) => {

    const topBar = new TopMenuProfilePage(page);
    const loginForm = new LoginFormPageModel(page);

    const loginAsCanViewUser = async () => {
      await topBar.logout();
      await loginForm.login('jean.michel@filigran.test', 'jeanmichel');
    };
    const loginAsCanEditUser = async () => {
      await topBar.logout();
      await loginForm.login('anne@filigran.test', 'anne');      
    };
    const loginAsCanManageUser = async () => {
      await topBar.logout();
      await loginForm.login('louise@filigran.test', 'louise');
    };

    const loginAsAdmin = async () => {
      await topBar.logout();
      await loginForm.login();
    };

    // create a draft with restrictions
    const Drafts = new DraftsPage(page);
    const Restrictions = new RestrictionsPage(page);

    await Drafts.navigate();
    await Drafts.createDraft({
      name: draftName,
      authorizedMembers: [],
    });
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    // enter draft context
    await Drafts.getDraft(draftName).click();
    
    // set restrictions
    await Drafts.setDraftRestrictions([
      { name: 'Jean Michel', permission: 'can view' },
      { name: 'Anne', permission: 'can edit' },
      { name: 'Louise', permission: 'can manage' },
    ]);

    // verify restrictions as different users
    await loginAsCanViewUser();
    await Drafts.navigate();
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    await loginAsCanEditUser();
    await Drafts.navigate();
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    await loginAsCanManageUser();
    await Drafts.navigate();
    await expect(Drafts.getDraft(draftName)).toBeVisible();

    // verify draft is listed in restricted drafts
    await loginAsAdmin();
    await Restrictions.navigateToRestrictedDrafts();
    await expect(Restrictions.getDraft(draftName)).toBeVisible();

    // clean up by deleting the created draft
    await Restrictions.removeRestrictionsOnDraft(draftName);
    await page.reload();
    await expect(Restrictions.getDraft(draftName)).not.toBeVisible();
  });

});
