import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import PirPage from '../model/pir.pageModel';
import IntelligenceRequirementPageModel from '../model/intelligenceRequirement.pageModel';
import { addRelationship, deleteRelationship } from '../dataForTesting/relationship.data';
import { executeGraphql } from '../dataForTesting/query-utils';
import { awaitUntilCondition } from '../utils';

const FLAGGED_MALWARE = 'E2E dashboard - Malware - month ago';
const TARGETED_LOCATION = 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971';

/** Create a threat landscape PIR on one location through the PIR API, the contract consumers keep calling. */
const createPir = async (request: Parameters<typeof executeGraphql>[0], name: string) => {
  const { stixCoreObject } = await executeGraphql<{ stixCoreObject: { id: string } | null }>(
    request,
    'stixCoreObject',
    'query E2EPirLocation($id: String!) { stixCoreObject(id: $id) { id } }',
    { id: TARGETED_LOCATION },
  );
  if (!stixCoreObject) throw new Error(`Location ${TARGETED_LOCATION} not found`);
  await executeGraphql(request, 'pirAdd', 'mutation E2EPirAdd($input: PirAddInput!) { pirAdd(input: $input) { id } }', {
    input: {
      name,
      pir_type: 'THREAT_LANDSCAPE',
      description: 'e2e PIR description',
      pir_rescan_days: 0,
      pir_criteria: [{
        weight: 1,
        filters: {
          mode: 'and',
          filterGroups: [],
          filters: [
            { key: ['entity_type'], values: ['targets'], operator: 'eq', mode: 'or' },
            { key: ['toId'], values: [stixCoreObject.id], operator: 'eq', mode: 'or' },
          ],
        },
      }],
      pir_filters: { mode: 'and', filterGroups: [], filters: [{ key: ['confidence'], values: ['0'], operator: 'gte', mode: 'or' }] },
    },
  });
};

const deletePirByName = async (request: Parameters<typeof executeGraphql>[0], name: string) => {
  const data = await executeGraphql<{ pirs: { edges: { node: { id: string; name: string } }[] } }>(
    request,
    'pirs',
    'query E2EPirsByName($search: String) { pirs(search: $search, first: 10) { edges { node { id name } } } }',
    { search: name },
  );
  const pir = data.pirs.edges.map((e) => e.node).find((node) => node.name === name);
  if (!pir) throw new Error(`PIR ${name} not found`);
  await executeGraphql(request, 'pirDelete', 'mutation E2EPirDelete($id: ID!) { pirDelete(id: $id) }', { id: pir.id });
};

/**
 * Content of the test
 * -------------------
 * The PIR list URL redirects to the intelligence requirements, opened from the left menu
 * Create a PIR through the PIR API
 * Open it from the list: it is read on the screen of its intelligence requirement
 * Navigate through the requirement tabs
 * Flag an entity with a relationship, then unflag it
 * Delete the PIR
 */
test('Pir CRUD', { tag: ['@pir', '@mutation', '@ee'] }, async ({ page, request }) => {
  const leftNavigation = new LeftBarPage(page);
  const pirPage = new PirPage(page);
  const requirement = new IntelligenceRequirementPageModel(page);

  // One PIR concept: the old list URL lands on the intelligence requirements
  await pirPage.goto();
  await page.waitForURL(/\/dashboard\/intelligence_requirements$/);
  await pirPage.navigateFromMenu();
  await page.waitForURL(/\/dashboard\/intelligence_requirements$/);
  // open nav bar once and for all
  await leftNavigation.open();

  // region Create PIR
  // -----------------

  const pirName = `PIR - ${uuid()}`;
  await createPir(request, pirName);

  // The PIR is listed and read on the screen of its intelligence requirement
  await pirPage.goto();
  await pirPage.getItemFromList(pirName).click();
  await page.waitForURL(/\/dashboard\/intelligence_requirements\/[^/]+/);
  await expect(requirement.getTitle(pirName)).toBeVisible();
  const basePath = requirement.basePath();

  // ---------
  // endregion

  // region Navigate through tabs
  // ----------------------------

  await requirement.goToTab('Entities');
  await page.waitForURL(`**${basePath}/entities`);
  await requirement.goToTab('Timeline');
  await page.waitForURL(`**${basePath}/timeline`);
  await requirement.goToTab('Inbox');
  await page.waitForURL(`**${basePath}/inbox`);
  await requirement.goToTab('Overview');
  await expect(requirement.getTitle(pirName)).toBeVisible();

  // ---------
  // endregion

  // region Create a relation that flags entity
  // ------------------------------------------

  await requirement.gotoEntities(basePath);
  await expect(requirement.getEntity(FLAGGED_MALWARE)).toBeHidden();
  await addRelationship(request, {
    relationship_type: 'targets',
    toId: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971',
    fromId: 'malware--48534a79-a9d7-4c34-a292-f5f102d26dea',
    createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
  });

  // The requirement engine reads the stream: poll until the malware enters the requirement
  const waitForFlagging = async () => {
    await requirement.gotoEntities(basePath);
    return requirement.getEntity(FLAGGED_MALWARE).isVisible();
  };
  await awaitUntilCondition(waitForFlagging, 2000, 15);
  await expect(requirement.getEntity(FLAGGED_MALWARE)).toBeVisible();

  // ---------
  // endregion

  // region Delete relation that flags entity
  // ----------------------------------------

  await deleteRelationship(request, {
    relationship_type: 'targets',
    toId: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971',
    fromId: 'malware--48534a79-a9d7-4c34-a292-f5f102d26dea',
  });

  const waitForUnflagging = async () => {
    await requirement.gotoEntities(basePath);
    return !(await requirement.getEntity(FLAGGED_MALWARE).isVisible());
  };
  await awaitUntilCondition(waitForUnflagging, 2000, 15);
  await expect(requirement.getEntity(FLAGGED_MALWARE)).toBeHidden();

  // ---------
  // endregion

  // region Delete the PIR
  // ---------------------

  // Deleting the PIR deletes its requirement and everything stored for it
  await deletePirByName(request, pirName);
  await pirPage.goto();
  await expect(pirPage.getItemFromList(pirName)).toBeHidden();

  // ---------
  // endregion
});
