import { expect, test } from '../../fixtures/baseFixtures';
import { graphqlRequest } from '../../dataForTesting/graphql.data';
import { addRoles } from '../../dataForTesting/role.data';
import { addGroups } from '../../dataForTesting/group.data';
import { addUsers } from '../../dataForTesting/user.data';
import LeftBarPage from '../../model/menu/leftBar.pageModel';
import TopMenuProfilePage from '../../model/menu/topMenuProfile.pageModel';
import LoginFormPageModel from '../../model/form/loginForm.pageModel';
import ThreatActorGroupPage from '../../model/threatActorGroup.pageModel';

/**
 * Scenario: merge-denied-restricted-role
 * Context: a restricted test user with no KNOWLEDGE_KNUPDATE_KNMERGE capability, two
 *   existing Threat Actor Groups (MERGE_TEST_SOURCE, MERGE_TEST_TARGET) created by an
 *   admin
 * Action: select both entities individually in Lines view, attempt to open Merge
 * Success: the Merge control is disabled and no merge mutation is sent
 *
 * No existing page object exposes per-row selection or the toolbar's Merge
 * control, so this test adds locators for them directly.
 */

const RESTRICTED_ROLE_NAME = 'Merge denied test role';
const RESTRICTED_GROUP_NAME = 'Merge denied test group';
const RESTRICTED_USER_EMAIL = 'merge.denied@filigran.test';
const RESTRICTED_USER_PASSWORD = 'mergedenied';

const SOURCE_ENTITY_NAME = 'MERGE_TEST_SOURCE';
const TARGET_ENTITY_NAME = 'MERGE_TEST_TARGET';

interface IdNode { id: string }

const addThreatActorGroupMutation = (name: string) => `
  mutation {
    threatActorGroupAdd(input: { name: "${name}" }) {
      id
    }
  }
`;

const deleteThreatActorGroupMutation = (id: string) => `
  mutation {
    threatActorGroupEdit(id: "${id}") {
      delete
    }
  }
`;

test('merge is denied for a restricted role', { tag: ['@ce', '@agentic'] }, async ({ page, request }) => {
  // region Prepare the two Threat Actor Groups and the restricted user, as admin
  // -----------------------------------------------------------------------
  const { threatActorGroupAdd: source } = await graphqlRequest<{ threatActorGroupAdd: IdNode }>(
    request,
    addThreatActorGroupMutation(SOURCE_ENTITY_NAME),
    `create threat actor group ${SOURCE_ENTITY_NAME}`,
  );
  const { threatActorGroupAdd: target } = await graphqlRequest<{ threatActorGroupAdd: IdNode }>(
    request,
    addThreatActorGroupMutation(TARGET_ENTITY_NAME),
    `create threat actor group ${TARGET_ENTITY_NAME}`,
  );

  await addRoles(request, [
    { name: RESTRICTED_ROLE_NAME, capabilities: ['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE'] },
  ]);
  await addGroups(request, [
    { name: RESTRICTED_GROUP_NAME, roles: [RESTRICTED_ROLE_NAME] },
  ]);
  await addUsers(request, [
    {
      name: 'Merge Denied User',
      user_email: RESTRICTED_USER_EMAIL,
      password: RESTRICTED_USER_PASSWORD,
      groups: [RESTRICTED_GROUP_NAME],
    },
  ]);
  // ---------
  // endregion

  const leftBar = new LeftBarPage(page);
  const topBar = new TopMenuProfilePage(page);
  const loginForm = new LoginFormPageModel(page);
  const threatActorGroupPage = new ThreatActorGroupPage(page);

  // region Log in as the restricted user and reach the Lines view
  // ---------------------------------------------------------------
  await page.goto('/dashboard/threats/threat_actors_group');
  await topBar.logout();
  await loginForm.login(RESTRICTED_USER_EMAIL, RESTRICTED_USER_PASSWORD);
  await leftBar.clickOnMenu('Threats', 'Threat actors (group)');
  await threatActorGroupPage.getPage().waitFor({ state: 'visible' });
  // ---------
  // endregion

  // region Select both entities individually and attempt to open Merge
  // ----------------------------------------------------------------
  await page.getByTestId(SOURCE_ENTITY_NAME).getByRole('checkbox').click();
  await page.getByTestId(TARGET_ENTITY_NAME).getByRole('checkbox').click();

  const mergeMutationRequests: string[] = [];
  page.on('request', (req) => {
    if (req.method() === 'POST' && req.url().includes('/graphql')) {
      const body = req.postData() ?? '';
      if (body.includes('MERGE')) {
        mergeMutationRequests.push(body);
      }
    }
  });

  const mergeButton = page.getByLabel('merge');
  await mergeButton.click({ force: true }).catch(() => {});
  // ---------
  // endregion

  await expect(mergeButton).toBeDisabled();
  expect(mergeMutationRequests).toHaveLength(0);

  // region Clean up: restore admin session and remove the created entities
  // ----------------------------------------------------------------------
  await topBar.logout();
  await loginForm.login();
  await graphqlRequest(request, deleteThreatActorGroupMutation(source.id), `delete threat actor group ${SOURCE_ENTITY_NAME}`);
  await graphqlRequest(request, deleteThreatActorGroupMutation(target.id), `delete threat actor group ${TARGET_ENTITY_NAME}`);
  // ---------
  // endregion
});
